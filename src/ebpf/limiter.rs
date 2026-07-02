// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF limiter — token-bucket rate enforcement per cgroup.
//!
//! Wolf Architecture Layer 0 (enforcement) + Layer 1 (map interface).
//!
//! Loads `limiter.bpf.o`, attaches to `cgroup_skb/egress`, writes policies
//! to the `cgroup_policy` map, and reads enforcement stats from
//! `cgroup_limiter_stats`.
//!
//! # Fail-Safe Design
//!
//! The BPF program always returns `1` (allow) on any error path: no policy,
//! bucket creation failure, map lookup failure. Enforcement is a privilege;
//! availability trumps enforcement on failure.
//!
//! # Policy Lifetime
//!
//! Policies are **ephemeral** in this phase: they live in the BPF map for
//! the duration of the `enforce` command. When zelynic exits, the BPF
//! program is unloaded and all policies are lost. Future work: BPF map
//! pinning for persistent policies.

use anyhow::{anyhow, bail, Context, Result};
use aya::{
    maps::{Array as BpfArray, HashMap as BpfHashMap},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf,
};
use std::fs::File;
use std::path::PathBuf;

use crate::ebpf::identity::IdentityMap;

const BPF_OBJECT_PATH: &str = "bpf/limiter.bpf.o";

/// Per-cgroup policy. Must match `struct policy` in `limiter.bpf.c`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct PolicyRaw {
    pub rate_bps: u64,
    pub burst_bytes: u64,
}

unsafe impl aya::Pod for PolicyRaw {}

/// Per-cgroup bucket state. Must match `struct bucket` in `limiter.bpf.c`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct BucketRaw {
    pub tokens: u64,
    pub last_refill_ns: u64,
}

unsafe impl aya::Pod for BucketRaw {}

/// Per-cgroup enforcement stats. Must match `struct limiter_stats`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct LimiterStatsRaw {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub bytes_allowed: u64,
    pub bytes_dropped: u64,
}

unsafe impl aya::Pod for LimiterStatsRaw {}

/// A parsed rate limit policy.
#[derive(Debug, Clone)]
pub struct Policy {
    pub cgroup_id: u32,
    pub rate_bps: u64,
    pub burst_bytes: u64,
}

/// Parsed policy spec from CLI (before cgroup resolution).
#[derive(Debug, Clone)]
pub struct PolicySpec {
    /// Raw cgroup ID (if numeric) or process name (if string).
    pub target: String,
    pub rate_bps: u64,
    pub burst_bytes: u64,
}

/// eBPF limiter — loads BPF program, writes policies, reads stats.
pub struct Limiter {
    bpf: Option<Ebpf>,
    cgroup_path: String,
    identity: IdentityMap,
}

impl Limiter {
    /// Load limiter BPF object and attach to cgroup v2 root.
    pub fn attach() -> Result<Self> {
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        let obj_path = find_bpf_object()?;
        eprintln!("[limiter] Loading BPF object from {}", obj_path.display());
        let obj_data = std::fs::read(&obj_path)
            .context(format!("Failed to read BPF object: {}", obj_path.display()))?;

        let mut bpf = Ebpf::load(&obj_data).context("Failed to load BPF object")?;

        let program: &mut CgroupSkb = bpf
            .program_mut("enforce_limit")
            .context("BPF program 'enforce_limit' not found")?
            .try_into()?;

        program.load()?;

        let cgroup_file =
            File::open(cgroup_path).context("Failed to open cgroup root directory")?;

        let _link_id = program
            .attach(
                cgroup_file,
                CgroupSkbAttachType::Egress,
                CgroupAttachMode::default(),
            )
            .context("Failed to attach BPF program to cgroup")?;

        eprintln!("[limiter] Enforcer attached to {cgroup_path}");

        let mut limiter = Limiter {
            bpf: Some(bpf),
            cgroup_path: cgroup_path.to_string(),
            identity: IdentityMap::new(),
        };

        // Prime identity map for policy resolution.
        let resolved = limiter.identity.refresh();
        eprintln!("[limiter] Identity map: {} cgroups resolved", resolved);

        Ok(limiter)
    }

    /// Apply a list of policies. Resolves process names to cgroup IDs via
    /// the identity map, then writes to the cgroup_policy BPF map.
    ///
    /// Two-phase to avoid borrow conflict:
    ///   Phase 1: resolve all targets (needs &mut self for identity refresh)
    ///   Phase 2: write to BPF map (needs &mut self.bpf via map_mut)
    pub fn apply_policies(&mut self, specs: &[PolicySpec]) -> Result<usize> {
        // Phase 1: resolve all targets.
        let mut resolved: Vec<(u32, PolicyRaw, String)> = Vec::new();
        for spec in specs {
            let cgroup_ids = self.resolve_target(&spec.target)?;
            if cgroup_ids.is_empty() {
                eprintln!(
                    "[limiter] WARNING: no cgroup found for '{}' — skipping",
                    spec.target
                );
                continue;
            }
            for cgroup_id in cgroup_ids {
                let label = self.identity.label(cgroup_id);
                let raw = PolicyRaw {
                    rate_bps: spec.rate_bps,
                    burst_bytes: spec.burst_bytes,
                };
                resolved.push((cgroup_id, raw, label));
            }
        }

        // Phase 2: write to BPF map.
        let bpf = self
            .bpf
            .as_mut()
            .context("BPF not loaded — call attach() first")?;

        let mut policy_map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
            bpf.map_mut("cgroup_policy")
                .context("cgroup_policy map not found")?,
        )
        .context("Failed to access cgroup_policy map")?;

        let mut applied = 0usize;
        for (cgroup_id, raw, label) in resolved {
            // BPF_ANY = 0 (create or update)
            policy_map
                .insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("Failed to write policy for {label}: {e}"))?;

            eprintln!(
                "[limiter] Policy set: {label} → rate={} burst={}",
                format_rate(raw.rate_bps),
                format_bytes(raw.burst_bytes),
            );
            applied += 1;
        }

        Ok(applied)
    }

    /// Refresh the watchdog deadline. If userspace stops refreshing,
    /// the BPF program auto-disables (becomes no-op) after the timeout.
    ///
    /// CRITICAL: This is zelynic's safety net. If zelynic crashes, freezes,
    /// or is kill -9'd, the watchdog expires and all traffic resumes
    /// automatically — no manual `bpftool prog unload` needed.
    ///
    /// Uses CLOCK_MONOTONIC to match bpf_ktime_get_ns().
    ///
    /// Note: watchdog_deadline is a BPF_MAP_TYPE_ARRAY (single entry at index 0),
    /// so we use aya::maps::Array, not HashMap.
    pub fn refresh_watchdog(&mut self, timeout_secs: u64) -> Result<()> {
        let bpf = self.bpf.as_mut().context("BPF not loaded")?;
        let mut watchdog: BpfArray<_, u64> = BpfArray::try_from(
            bpf.map_mut("watchdog_deadline")
                .context("watchdog_deadline map not found")?,
        )
        .context("Failed to access watchdog_deadline map")?;

        let now = monotonic_ns();
        let deadline = now.saturating_add(timeout_secs.saturating_mul(1_000_000_000));

        // Array map: set(index, value, flags). Index 0 = the single entry.
        watchdog
            .set(0, deadline, 0)
            .map_err(|e| anyhow!("Failed to refresh watchdog: {e}"))?;
        Ok(())
    }

    /// Resolve a target string to cgroup ID(s).
    /// - Numeric string → single cgroup ID (parsed directly).
    /// - Process name → all cgroup IDs whose comm matches.
    fn resolve_target(&mut self, target: &str) -> Result<Vec<u32>> {
        // Try parsing as numeric cgroup ID first.
        if let Ok(id) = target.parse::<u32>() {
            return Ok(vec![id]);
        }

        // Otherwise, treat as process name — find all matching cgroups.
        self.identity.maybe_refresh();

        let target_lower = target.to_lowercase();
        let matches: Vec<u32> = self
            .identity
            .all()
            .iter()
            .filter(|id| id.comm.to_lowercase() == target_lower)
            .map(|id| id.cgroup_id)
            .collect();

        Ok(matches)
    }

    /// Read enforcement stats from BPF map.
    pub fn read_stats(&self) -> Result<Vec<(u32, LimiterStatsRaw)>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, LimiterStatsRaw> = BpfHashMap::try_from(
            bpf.map("cgroup_limiter_stats")
                .context("cgroup_limiter_stats map not found")?,
        )
        .context("Failed to access cgroup_limiter_stats map")?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read bucket state from BPF map (diagnostic).
    pub fn read_buckets(&self) -> Result<Vec<(u32, BucketRaw)>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, BucketRaw> = BpfHashMap::try_from(
            bpf.map("cgroup_bucket")
                .context("cgroup_bucket map not found")?,
        )
        .context("Failed to access cgroup_bucket map")?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Print enforcement stats summary.
    pub fn print_stats(&self) {
        let stats = match self.read_stats() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[limiter] Failed to read stats: {e}");
                return;
            }
        };

        if stats.is_empty() {
            println!("\n  (no cgroups with active policies)");
            return;
        }

        println!("\n━━━ eBPF Enforcement Stats ━━━");

        let mut sorted = stats;
        sorted.sort_by_key(|(_, s)| std::cmp::Reverse(s.bytes_allowed + s.bytes_dropped));

        println!(
            "  {:<30} {:>8} {:>10} {:>10} {:>10}",
            "CGROUP", "ALLOWED", "ALLOWED B", "DROPPED", "DROPPED B"
        );
        println!("  {}", "─".repeat(72));

        for (cgroup_id, s) in sorted.iter().take(20) {
            let label = self.identity.label(*cgroup_id);
            println!(
                "  {:<30} {:>8} {:>10} {:>10} {:>10}",
                label,
                s.packets_allowed,
                format_bytes(s.bytes_allowed),
                s.packets_dropped,
                format_bytes(s.bytes_dropped),
            );
        }
    }

    /// Read current watchdog deadline (monotonic ns). Returns None if not set.
    ///
    /// Note: watchdog_deadline is a BPF_MAP_TYPE_ARRAY, so we use aya::maps::Array.
    /// Array::get takes &u32 (index reference), not a key value.
    pub fn read_watchdog(&self) -> Result<Option<u64>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfArray<_, u64> = BpfArray::try_from(
            bpf.map("watchdog_deadline")
                .context("watchdog_deadline map not found")?,
        )
        .context("Failed to access watchdog_deadline map")?;

        // Array::get takes &u32 index. Index 0 = the single entry.
        let index: u32 = 0;
        match map.get(&index, 0) {
            Ok(deadline) => Ok(Some(deadline)),
            Err(_) => Ok(None),
        }
    }

    /// Print watchdog status alongside stats.
    pub fn print_watchdog_status(&self) {
        match self.read_watchdog() {
            Ok(Some(deadline)) => {
                let now = monotonic_ns();
                if deadline > now {
                    let remaining_secs = (deadline - now) / 1_000_000_000;
                    eprintln!("[limiter] Watchdog: {remaining_secs}s remaining");
                } else {
                    eprintln!("[limiter] Watchdog: EXPIRED (BPF is no-op)");
                }
            }
            Ok(None) => {
                eprintln!("[limiter] Watchdog: not set (BPF is no-op)");
            }
            Err(e) => {
                eprintln!("[limiter] Watchdog: read error: {e}");
            }
        }
    }

    /// Borrow identity map (read-only).
    pub fn identity(&self) -> &IdentityMap {
        &self.identity
    }

    /// Detach BPF program.
    pub fn detach(&mut self) {
        self.bpf = None;
        eprintln!("[limiter] Enforcer detached from {}", self.cgroup_path);
    }
}

impl Drop for Limiter {
    fn drop(&mut self) {
        if self.bpf.is_some() {
            eprintln!("[limiter] Cleaning up BPF programs");
            self.bpf = None;
        }
    }
}

/// Find the limiter BPF object file.
fn find_bpf_object() -> Result<PathBuf> {
    let candidates = [
        PathBuf::from(BPF_OBJECT_PATH),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BPF_OBJECT_PATH),
        PathBuf::from("/usr/lib/zelynic/limiter.bpf.o"),
        PathBuf::from("/usr/local/lib/zelynic/limiter.bpf.o"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    bail!(
        "BPF object file not found. Compile with:\n  \
         clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o\n  \
         Searched: {:?}",
        candidates
    )
}

/// Parse a rate string like "1MB/s", "500KB/s", "10MB/s" into bytes per second.
/// Supports: B/s, KB/s, MB/s, GB/s (case-insensitive).
/// Also accepts plain numbers (interpreted as bytes per second).
pub fn parse_rate(s: &str) -> Result<u64> {
    let s = s.trim();

    // Plain number = bytes per second.
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    let upper = s.to_uppercase();

    let (num_part, multiplier) = if let Some(v) = upper.strip_suffix("GB/S") {
        (v, 1_000_000_000u64)
    } else if let Some(v) = upper.strip_suffix("MB/S") {
        (v, 1_000_000u64)
    } else if let Some(v) = upper.strip_suffix("KB/S") {
        (v, 1_000u64)
    } else if let Some(v) = upper.strip_suffix("B/S") {
        (v, 1u64)
    } else {
        bail!(
            "Invalid rate format '{}'. Use formats like: 1MB/s, 500KB/s, 1000000",
            s
        );
    };

    let n: u64 = num_part
        .trim()
        .parse()
        .map_err(|e| anyhow!("Invalid number in rate '{}': {}", s, e))?;

    Ok(n.saturating_mul(multiplier))
}

/// Parse a policy spec string like "firefox:1MB/s" or "73386:500KB/s".
/// Returns (target, rate_bps).
pub fn parse_policy_spec(s: &str) -> Result<(String, u64)> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        bail!(
            "Invalid policy format '{}'. Use: <cgroup_id|process_name>:<rate>",
            s
        );
    }
    let target = parts[0].trim().to_string();
    let rate_bps = parse_rate(parts[1].trim())?;
    Ok((target, rate_bps))
}

/// Compute a burst size from a rate. Default burst = 1 second of traffic,
/// capped at a minimum of 4096 bytes (one typical packet) and a maximum
/// of 100 MB (pre runaway memory in BPF map).
pub fn default_burst(rate_bps: u64) -> u64 {
    let burst = rate_bps; // 1 second of traffic
    burst.clamp(4096, 100_000_000)
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_rate(bps: u64) -> String {
    format!("{}/s", format_bytes(bps))
}

/// Get monotonic time in nanoseconds. Matches `bpf_ktime_get_ns()` which
/// uses CLOCK_MONOTONIC (time since boot, excluding suspend).
///
/// Used for watchdog deadline calculations — userspace and BPF must use
/// the same clock for the deadline comparison to work.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with a valid clock ID and valid pointer is safe.
    // CLOCK_MONOTONIC is guaranteed to exist on Linux.
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            // Should never happen on Linux. Return 0 as fallback —
            // this will cause the watchdog to immediately "expire" in BPF,
            // which is the safe direction (allow all traffic).
            return 0;
        }
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rate_plain_number() {
        assert_eq!(parse_rate("1000000").unwrap(), 1_000_000);
    }

    #[test]
    fn test_parse_rate_bytes() {
        assert_eq!(parse_rate("500B/s").unwrap(), 500);
    }

    #[test]
    fn test_parse_rate_kilobytes() {
        assert_eq!(parse_rate("1KB/s").unwrap(), 1_000);
        assert_eq!(parse_rate("500KB/s").unwrap(), 500_000);
    }

    #[test]
    fn test_parse_rate_megabytes() {
        assert_eq!(parse_rate("1MB/s").unwrap(), 1_000_000);
        assert_eq!(parse_rate("5MB/s").unwrap(), 5_000_000);
    }

    #[test]
    fn test_parse_rate_gigabytes() {
        assert_eq!(parse_rate("1GB/s").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_rate_case_insensitive() {
        assert_eq!(parse_rate("1mb/s").unwrap(), 1_000_000);
        assert_eq!(parse_rate("1Mb/S").unwrap(), 1_000_000);
        assert_eq!(parse_rate("1Gb/s").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_rate_with_spaces() {
        assert_eq!(parse_rate("  1 MB/s  ").unwrap(), 1_000_000);
    }

    #[test]
    fn test_parse_rate_invalid() {
        assert!(parse_rate("abc").is_err());
        assert!(parse_rate("1XB/s").is_err());
        assert!(parse_rate("").is_err());
    }

    #[test]
    fn test_parse_policy_spec_numeric() {
        let (target, rate) = parse_policy_spec("73386:1MB/s").unwrap();
        assert_eq!(target, "73386");
        assert_eq!(rate, 1_000_000);
    }

    #[test]
    fn test_parse_policy_spec_process_name() {
        let (target, rate) = parse_policy_spec("firefox:500KB/s").unwrap();
        assert_eq!(target, "firefox");
        assert_eq!(rate, 500_000);
    }

    #[test]
    fn test_parse_policy_spec_no_colon() {
        assert!(parse_policy_spec("firefox1MB/s").is_err());
    }

    #[test]
    fn test_parse_policy_spec_empty_target() {
        let (target, _) = parse_policy_spec(":1MB/s").unwrap();
        assert_eq!(target, "");
    }

    #[test]
    fn test_default_burst_normal_rate() {
        // 1MB/s → burst = 1MB (1 second of traffic)
        assert_eq!(default_burst(1_000_000), 1_000_000);
    }

    #[test]
    fn test_default_burst_minimum() {
        // Very low rate → burst clamped to 4096 (minimum packet)
        assert_eq!(default_burst(100), 4096);
    }

    #[test]
    fn test_default_burst_maximum() {
        // Very high rate → burst clamped to 100MB
        assert_eq!(default_burst(1_000_000_000_000), 100_000_000);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1_000_000), "976.6 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
    }

    #[test]
    fn test_format_rate() {
        assert_eq!(format_rate(1_000_000), "976.6 KB/s");
        assert_eq!(format_rate(0), "0 B/s");
    }
}
