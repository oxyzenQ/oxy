// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF limiter — token-bucket rate enforcement per cgroup or per group.
//!
//! Wolf Architecture Layer 0 (enforcement) + Layer 1 (map interface).
//!
//! Two enforcement modes:
//!   - **strict-single**: one cgroup, individual token bucket
//!   - **strict-multi**: multiple cgroups share one group token bucket
//!
//! Two directions:
//!   - **download** (ingress): `enforce_dl` BPF program, `*_dl` maps
//!   - **upload** (egress): `enforce_ul` BPF program, `*_ul` maps

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

// ━━ Rate bounds ━━

/// Minimum allowed rate: 1 KB/s. Below this = brick.
pub const MIN_RATE: u64 = 1024;

/// Maximum allowed rate: 1 GB/s. Above this = don't limit.
pub const MAX_RATE: u64 = 1_000_000_000;

// ━━ BPF map value structs (must match C structs) ━━

/// Per-cgroup policy. Must match `struct policy` in `limiter.bpf.c`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct PolicyRaw {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub group_id: u32,
}

unsafe impl aya::Pod for PolicyRaw {}

/// Token bucket state. Must match `struct bucket`.
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

// ━━ High-level API types ━━

/// A rate limit specification (download and/or upload).
#[derive(Debug, Clone)]
pub struct RateSpec {
    pub download: Option<u64>, // bytes/sec, None = no limit
    pub upload: Option<u64>,   // bytes/sec, None = no limit
}

/// A target spec: process name or cgroup ID.
#[derive(Debug, Clone)]
pub enum Target {
    CgroupId(u32),
    ProcessName(String),
}

impl Target {
    /// Parse a target string. Numeric = cgroup ID, otherwise process name.
    pub fn parse(s: &str) -> Self {
        if let Ok(id) = s.parse::<u32>() {
            Target::CgroupId(id)
        } else {
            Target::ProcessName(s.to_string())
        }
    }
}

/// Resolved policy ready to write to BPF map.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub cgroup_id: u32,
    pub comm: String,
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub group_id: u32,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    fn suffix(&self) -> &'static str {
        match self {
            Direction::Download => "dl",
            Direction::Upload => "ul",
        }
    }
}

// ━━ Limiter struct ━━

pub struct Limiter {
    bpf: Option<Ebpf>,
    cgroup_path: String,
    identity: IdentityMap,
    verbose: bool,
}

impl Limiter {
    /// Load limiter BPF object and attach to cgroup v2 root (both ingress + egress).
    pub fn attach(verbose: bool) -> Result<Self> {
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        let obj_path = find_bpf_object()?;
        if verbose {
            eprintln!("[limiter] Loading BPF object from {}", obj_path.display());
        }
        let obj_data = std::fs::read(&obj_path)
            .context(format!("Failed to read BPF object: {}", obj_path.display()))?;

        let mut bpf = Ebpf::load(&obj_data).context("Failed to load BPF object")?;

        // Load and attach download program (ingress).
        let dl_prog: &mut CgroupSkb = bpf
            .program_mut("enforce_dl")
            .context("BPF program 'enforce_dl' not found")?
            .try_into()?;
        dl_prog.load()?;

        let cgroup_file =
            File::open(cgroup_path).context("Failed to open cgroup root directory")?;

        dl_prog
            .attach(
                cgroup_file.try_clone()?,
                CgroupSkbAttachType::Ingress,
                CgroupAttachMode::default(),
            )
            .context("Failed to attach enforce_dl (ingress)")?;

        // Load and attach upload program (egress).
        let ul_prog: &mut CgroupSkb = bpf
            .program_mut("enforce_ul")
            .context("BPF program 'enforce_ul' not found")?
            .try_into()?;
        ul_prog.load()?;

        ul_prog
            .attach(
                cgroup_file,
                CgroupSkbAttachType::Egress,
                CgroupAttachMode::default(),
            )
            .context("Failed to attach enforce_ul (egress)")?;

        eprintln!("[limiter] Attached to {cgroup_path} (ingress + egress)");

        let mut limiter = Limiter {
            bpf: Some(bpf),
            cgroup_path: cgroup_path.to_string(),
            identity: IdentityMap::new(),
            verbose,
        };

        let resolved = limiter.identity.refresh();
        if verbose {
            eprintln!("[limiter] Identity map: {} cgroups resolved", resolved);
        }

        Ok(limiter)
    }

    /// Apply strict-single: individual policy per cgroup.
    /// `target` is resolved to cgroup IDs. Each gets its own token bucket.
    pub fn apply_single(&mut self, target: &Target, rates: &RateSpec) -> Result<usize> {
        let cgroup_ids = self.resolve_target(target)?;
        if cgroup_ids.is_empty() {
            eprintln!(
                "[limiter] WARNING: no cgroup found for '{:?}' — skipping",
                target
            );
            return Ok(0);
        }

        let mut applied = 0usize;
        for cgroup_id in &cgroup_ids {
            let label = self.identity.label(*cgroup_id);

            if let Some(dl_rate) = rates.download {
                self.write_policy(*cgroup_id, dl_rate, 0, Direction::Download)?;
                eprintln!("[limiter] {label} download → {}/s", format_rate(dl_rate));
                applied += 1;
            }

            if let Some(ul_rate) = rates.upload {
                self.write_policy(*cgroup_id, ul_rate, 0, Direction::Upload)?;
                eprintln!("[limiter] {label} upload → {}/s", format_rate(ul_rate));
                applied += 1;
            }
        }

        Ok(applied)
    }

    /// Apply strict-multi: all cgroups share one group token bucket.
    /// A random group_id is generated. All cgroups get policy pointing to it.
    pub fn apply_group(&mut self, targets: &[Target], rates: &RateSpec) -> Result<usize> {
        // Resolve all targets to cgroup IDs.
        let mut all_cgroup_ids: Vec<u32> = Vec::new();
        for target in targets {
            let ids = self.resolve_target(target)?;
            if ids.is_empty() {
                eprintln!(
                    "[limiter] WARNING: no cgroup found for '{:?}' — skipping",
                    target
                );
                continue;
            }
            all_cgroup_ids.extend(ids);
        }

        if all_cgroup_ids.is_empty() {
            return Ok(0);
        }

        // Generate group_id (use PID + timestamp for uniqueness).
        let group_id = (std::process::id() as u32).wrapping_mul(1000).wrapping_add(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos())
                % 1000,
        );

        let mut applied = 0usize;
        for cgroup_id in &all_cgroup_ids {
            if let Some(dl_rate) = rates.download {
                self.write_policy(*cgroup_id, dl_rate, group_id, Direction::Download)?;
                applied += 1;
            }

            if let Some(ul_rate) = rates.upload {
                self.write_policy(*cgroup_id, ul_rate, group_id, Direction::Upload)?;
                applied += 1;
            }
        }

        let group_label = format!("group:{}", group_id);
        if let Some(dl_rate) = rates.download {
            eprintln!(
                "[limiter] {} download → {}/s (shared by {} cgroups)",
                group_label,
                format_rate(dl_rate),
                all_cgroup_ids.len()
            );
        }
        if let Some(ul_rate) = rates.upload {
            eprintln!(
                "[limiter] {} upload → {}/s (shared by {} cgroups)",
                group_label,
                format_rate(ul_rate),
                all_cgroup_ids.len()
            );
        }

        Ok(applied)
    }

    /// Remove policy for a target (unstrict).
    pub fn unstrict(&mut self, target: &Target) -> Result<usize> {
        let cgroup_ids = self.resolve_target(target)?;
        let mut removed = 0usize;

        for cgroup_id in &cgroup_ids {
            let label = self.identity.label(*cgroup_id);
            let mut found = false;

            // Remove from dl + ul policy maps.
            if self.delete_policy(*cgroup_id, Direction::Download).is_ok() {
                found = true;
            }
            if self.delete_policy(*cgroup_id, Direction::Upload).is_ok() {
                found = true;
            }

            if found {
                eprintln!("[limiter] Unstrict: {label} — limits removed");
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Remove ALL policies (unstrict-all).
    pub fn unstrict_all(&mut self) -> Result<usize> {
        let dl_count = self.clear_map("cgroup_policy_dl")?;
        let ul_count = self.clear_map("cgroup_policy_ul")?;
        let _ = self.clear_map("cgroup_bucket_dl")?;
        let _ = self.clear_map("cgroup_bucket_ul")?;
        let _ = self.clear_map("group_bucket_dl")?;
        let _ = self.clear_map("group_bucket_ul")?;
        let _ = self.clear_map("cgroup_limiter_stats")?;

        let total = dl_count + ul_count;
        eprintln!("[limiter] Unstrict-all: {} policies removed", total);
        Ok(total)
    }

    /// Print status: active limits + watchdog.
    pub fn print_status(&self) {
        let dl_policies = self.read_policies(Direction::Download).unwrap_or_default();
        let ul_policies = self.read_policies(Direction::Upload).unwrap_or_default();
        let stats = self.read_stats().unwrap_or_default();

        println!("\n━━━ zelynic Status ━━━");

        // Watchdog
        match self.read_watchdog() {
            Ok(Some(deadline)) => {
                let now = monotonic_ns();
                if deadline > now {
                    let remaining = (deadline - now) / 1_000_000_000;
                    println!("  Watchdog: {remaining}s remaining");
                } else {
                    println!("  Watchdog: EXPIRED (BPF is no-op)");
                }
            }
            _ => println!("  Watchdog: not set"),
        }

        if dl_policies.is_empty() && ul_policies.is_empty() {
            println!("  Active limits: none");
            return;
        }

        println!(
            "  Active limits: {} dl, {} ul",
            dl_policies.len(),
            ul_policies.len()
        );
        println!();

        // Combine dl + ul by cgroup_id.
        use std::collections::HashMap;
        let mut combined: HashMap<u32, (Option<u64>, Option<u64>)> = HashMap::new();
        for (id, p) in &dl_policies {
            combined.entry(*id).or_default().0 = Some(p.rate_bps);
        }
        for (id, p) in &ul_policies {
            combined.entry(*id).or_default().1 = Some(p.rate_bps);
        }

        let mut sorted: Vec<_> = combined.into_iter().collect();
        sorted.sort_by_key(|(id, _)| *id);

        println!(
            "  {:<30} {:>12} {:>12} {:>8} {:>8}",
            "CGROUP", "DOWNLOAD", "UPLOAD", "ALLOWED", "DROPPED"
        );
        println!("  {}", "─".repeat(74));

        for (cgroup_id, (dl, ul)) in &sorted {
            let label = self.identity.label(*cgroup_id);
            let dl_str = dl.map(format_rate).unwrap_or_else(|| "—".to_string());
            let ul_str = ul.map(format_rate).unwrap_or_else(|| "—".to_string());
            let s = stats.iter().find(|(id, _)| id == cgroup_id);
            let allowed = s.map(|(_, s)| s.packets_allowed).unwrap_or(0);
            let dropped = s.map(|(_, s)| s.packets_dropped).unwrap_or(0);
            println!(
                "  {:<30} {:>12} {:>12} {:>8} {:>8}",
                label, dl_str, ul_str, allowed, dropped
            );
        }
    }

    // ━━ Internal helpers ━━

    /// Resolve a target to cgroup IDs.
    fn resolve_target(&mut self, target: &Target) -> Result<Vec<u32>> {
        match target {
            Target::CgroupId(id) => Ok(vec![*id]),
            Target::ProcessName(name) => {
                self.identity.maybe_refresh();
                let name_lower = name.to_lowercase();
                let matches: Vec<u32> = self
                    .identity
                    .all()
                    .iter()
                    .filter(|id| id.comm.to_lowercase() == name_lower)
                    .map(|id| id.cgroup_id)
                    .collect();
                Ok(matches)
            }
        }
    }

    /// Write a policy to the appropriate BPF map.
    fn write_policy(
        &mut self,
        cgroup_id: u32,
        rate_bps: u64,
        group_id: u32,
        direction: Direction,
    ) -> Result<()> {
        let burst = default_burst(rate_bps);
        let raw = PolicyRaw {
            rate_bps,
            burst_bytes: burst,
            group_id,
        };

        let map_name = format!("cgroup_policy_{}", direction.suffix());
        let bpf = self.bpf.as_mut().context("BPF not loaded")?;
        let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
            bpf.map_mut(&map_name)
                .context(format!("{map_name} not found"))?,
        )
        .context(format!("Failed to access {map_name}"))?;

        map.insert(cgroup_id, raw, 0)
            .map_err(|e| anyhow!("Failed to write policy: {e}"))?;
        Ok(())
    }

    /// Delete a policy from BPF map.
    fn delete_policy(&mut self, cgroup_id: u32, direction: Direction) -> Result<()> {
        let map_name = format!("cgroup_policy_{}", direction.suffix());
        let bpf = self.bpf.as_mut().context("BPF not loaded")?;
        let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
            bpf.map_mut(&map_name)
                .context(format!("{map_name} not found"))?,
        )
        .context(format!("Failed to access {map_name}"))?;

        map.remove(&cgroup_id)
            .map_err(|e| anyhow!("Failed to delete policy: {e}"))?;
        Ok(())
    }

    /// Read all policies from a direction map.
    fn read_policies(&self, direction: Direction) -> Result<Vec<(u32, PolicyRaw)>> {
        let map_name = format!("cgroup_policy_{}", direction.suffix());
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
            bpf.map(&map_name)
                .context(format!("{map_name} not found"))?,
        )
        .context(format!("Failed to access {map_name}"))?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read enforcement stats.
    fn read_stats(&self) -> Result<Vec<(u32, LimiterStatsRaw)>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, LimiterStatsRaw> = BpfHashMap::try_from(
            bpf.map("cgroup_limiter_stats")
                .context("cgroup_limiter_stats not found")?,
        )
        .context("Failed to access cgroup_limiter_stats")?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Clear all entries from a map. Returns count removed.
    fn clear_map(&mut self, map_name: &str) -> Result<usize> {
        let bpf = self.bpf.as_mut().context("BPF not loaded")?;

        // Read all keys first.
        let keys: Vec<u32> = {
            let map: BpfHashMap<_, u32, PolicyRaw> =
                BpfHashMap::try_from(bpf.map(map_name).context(format!("{map_name} not found"))?)
                    .context(format!("Failed to access {map_name}"))?;
            map.iter().flatten().map(|(k, _)| k).collect()
        };

        let count = keys.len();

        // Delete each key.
        let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
            bpf.map_mut(map_name)
                .context(format!("{map_name} not found"))?,
        )
        .context(format!("Failed to access {map_name} (mut)"))?;
        for key in &keys {
            let _ = map.remove(key);
        }

        Ok(count)
    }

    /// Refresh the watchdog deadline.
    pub fn refresh_watchdog(&mut self, timeout_secs: u64) -> Result<()> {
        let bpf = self.bpf.as_mut().context("BPF not loaded")?;
        let mut watchdog: BpfArray<_, u64> = BpfArray::try_from(
            bpf.map_mut("watchdog_deadline")
                .context("watchdog_deadline not found")?,
        )
        .context("Failed to access watchdog_deadline")?;

        let now = monotonic_ns();
        let deadline = now.saturating_add(timeout_secs.saturating_mul(1_000_000_000));

        watchdog
            .set(0, deadline, 0)
            .map_err(|e| anyhow!("Failed to refresh watchdog: {e}"))?;
        Ok(())
    }

    /// Read current watchdog deadline.
    pub fn read_watchdog(&self) -> Result<Option<u64>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfArray<_, u64> = BpfArray::try_from(
            bpf.map("watchdog_deadline")
                .context("watchdog_deadline not found")?,
        )
        .context("Failed to access watchdog_deadline")?;

        let index: u32 = 0;
        match map.get(&index, 0) {
            Ok(deadline) => Ok(Some(deadline)),
            Err(_) => Ok(None),
        }
    }

    /// Borrow identity map.
    pub fn identity(&self) -> &IdentityMap {
        &self.identity
    }

    /// Force-refresh identity map. Returns number of cgroups resolved.
    pub fn refresh_identity(&mut self) -> usize {
        self.identity.refresh()
    }

    /// Detach BPF programs.
    pub fn detach(&mut self) {
        self.bpf = None;
        if self.verbose {
            eprintln!("[limiter] Detached from {}", self.cgroup_path);
        }
    }
}

impl Drop for Limiter {
    fn drop(&mut self) {
        if self.bpf.is_some() {
            self.bpf = None;
        }
    }
}

// ━━ Free functions ━━

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

/// Parse a rate string like "1MB/s", "500KB/s" into bytes per second.
pub fn parse_rate(s: &str) -> Result<u64> {
    let s = s.trim();

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
        bail!("Invalid rate format '{}'. Use: 1MB/s, 500KB/s, 1000000", s);
    };

    let n: u64 = num_part
        .trim()
        .parse()
        .map_err(|e| anyhow!("Invalid number in rate '{}': {}", s, e))?;

    Ok(n.saturating_mul(multiplier))
}

/// Validate rate is within bounds. Returns Ok(()) or error with message.
pub fn validate_rate(rate_bps: u64) -> Result<()> {
    if rate_bps < MIN_RATE {
        bail!(
            "Rate {} is below minimum ({} B/s = 1 KB/s).\n\
             Such a low rate will make the target unusable.\n\
             Use --allow-dangerous to override.",
            rate_bps,
            MIN_RATE
        );
    }
    if rate_bps > MAX_RATE {
        bail!(
            "Rate {} is above maximum ({} B/s = 1 GB/s).\n\
             Above this, just don't set a limit.",
            rate_bps,
            MAX_RATE
        );
    }
    Ok(())
}

/// Compute burst size: 1 second of traffic, clamped 4KB–100MB.
pub fn default_burst(rate_bps: u64) -> u64 {
    rate_bps.clamp(4096, 100_000_000)
}

/// Get monotonic time in nanoseconds (CLOCK_MONOTONIC, matches bpf_ktime_get_ns).
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return 0;
        }
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
}

pub fn format_bytes(bytes: u64) -> String {
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

pub fn format_rate(bps: u64) -> String {
    format!("{}/s", format_bytes(bps))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rate_plain_number() {
        assert_eq!(parse_rate("1000000").unwrap(), 1_000_000);
    }

    #[test]
    fn test_parse_rate_kb() {
        assert_eq!(parse_rate("1KB/s").unwrap(), 1_000);
        assert_eq!(parse_rate("500KB/s").unwrap(), 500_000);
    }

    #[test]
    fn test_parse_rate_mb() {
        assert_eq!(parse_rate("1MB/s").unwrap(), 1_000_000);
        assert_eq!(parse_rate("5MB/s").unwrap(), 5_000_000);
    }

    #[test]
    fn test_parse_rate_gb() {
        assert_eq!(parse_rate("1GB/s").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_rate_case_insensitive() {
        assert_eq!(parse_rate("1mb/s").unwrap(), 1_000_000);
        assert_eq!(parse_rate("1Gb/S").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_rate_invalid() {
        assert!(parse_rate("abc").is_err());
        assert!(parse_rate("1XB/s").is_err());
        assert!(parse_rate("").is_err());
    }

    #[test]
    fn test_validate_rate_minimum() {
        assert!(validate_rate(512).is_err()); // below 1KB
        assert!(validate_rate(1024).is_ok()); // exactly 1KB
    }

    #[test]
    fn test_validate_rate_maximum() {
        assert!(validate_rate(2_000_000_000).is_err()); // above 1GB
        assert!(validate_rate(1_000_000_000).is_ok()); // exactly 1GB
    }

    #[test]
    fn test_default_burst_normal() {
        assert_eq!(default_burst(1_000_000), 1_000_000);
    }

    #[test]
    fn test_default_burst_minimum() {
        assert_eq!(default_burst(100), 4096);
    }

    #[test]
    fn test_default_burst_maximum() {
        assert_eq!(default_burst(1_000_000_000_000), 100_000_000);
    }

    #[test]
    fn test_target_parse_numeric() {
        match Target::parse("73386") {
            Target::CgroupId(id) => assert_eq!(id, 73386),
            _ => panic!("expected CgroupId"),
        }
    }

    #[test]
    fn test_target_parse_name() {
        match Target::parse("firefox") {
            Target::ProcessName(name) => assert_eq!(name, "firefox"),
            _ => panic!("expected ProcessName"),
        }
    }

    #[test]
    fn test_direction_suffix() {
        assert_eq!(Direction::Download.suffix(), "dl");
        assert_eq!(Direction::Upload.suffix(), "ul");
    }
}
