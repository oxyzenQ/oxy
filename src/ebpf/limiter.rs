// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF limiter — token-bucket rate enforcement per cgroup or per group.
//!
//! Types and helpers in `limiter_types.rs`. This file contains the
//! `Limiter` struct and its implementation only.

use anyhow::{anyhow, bail, Context, Result};
use aya::{
    maps::{Array as BpfArray, HashMap as BpfHashMap, MapData},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf,
};
use std::fs::File;
use std::path::PathBuf;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter_types::{
    default_burst, find_bpf_object, monotonic_ns, BucketRaw, BPF_OBJECT_PATH,
};

// Re-export public types/functions for external use.
pub use crate::ebpf::limiter_types::{
    format_bytes, format_rate, parse_rate, validate_rate, Direction, LimiterStatsRaw, PolicyRaw,
    RateSpec, Target, MAX_RATE, MIN_RATE,
};

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

        if verbose {
            eprintln!("[limiter] Attached to {cgroup_path} (ingress + egress)");
        }

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
            return Ok(0);
        }

        let mut applied = 0usize;
        for cgroup_id in &cgroup_ids {
            if let Some(dl_rate) = rates.download {
                self.write_policy(*cgroup_id, dl_rate, 0, Direction::Download)?;
                applied += 1;
            }

            if let Some(ul_rate) = rates.upload {
                self.write_policy(*cgroup_id, ul_rate, 0, Direction::Upload)?;
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
                if self.verbose {
                    eprintln!("[limiter] no cgroup found for '{:?}' — skipping", target);
                }
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
        if self.verbose {
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
            if let Ok(deleted) = self.delete_policy(*cgroup_id, Direction::Download) {
                if deleted {
                    found = true;
                }
            }
            if let Ok(deleted) = self.delete_policy(*cgroup_id, Direction::Upload) {
                if deleted {
                    found = true;
                }
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
        // Clear policy maps (PolicyRaw, size 24).
        let dl_count = self.clear_policy_map("cgroup_policy_dl")?;
        let ul_count = self.clear_policy_map("cgroup_policy_ul")?;

        // Clear bucket maps (BucketRaw, size 16).
        let _ = self.clear_bucket_map("cgroup_bucket_dl");
        let _ = self.clear_bucket_map("cgroup_bucket_ul");
        let _ = self.clear_bucket_map("group_bucket_dl");
        let _ = self.clear_bucket_map("group_bucket_ul");

        // Clear stats map (LimiterStatsRaw, size 32).
        let _ = self.clear_stats_map("cgroup_limiter_stats");

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
            "  {:<30} {:>12} {:>12} {:>14} {:>14}",
            "CGROUP", "DOWNLOAD", "UPLOAD", "ALLOWED (pkts)", "DROPPED (pkts)"
        );
        println!("  {}", "─".repeat(86));

        for (cgroup_id, (dl, ul)) in &sorted {
            let label = self.identity.label(*cgroup_id);
            let dl_str = dl
                .map(|r| format!("{}/s", format_rate(r)))
                .unwrap_or_else(|| "—".to_string());
            let ul_str = ul
                .map(|r| format!("{}/s", format_rate(r)))
                .unwrap_or_else(|| "—".to_string());
            let s = stats.iter().find(|(id, _)| id == cgroup_id);
            let allowed_pkt = s.map(|(_, s)| s.packets_allowed).unwrap_or(0);
            let dropped_pkt = s.map(|(_, s)| s.packets_dropped).unwrap_or(0);
            let allowed_bytes = s.map(|(_, s)| s.bytes_allowed).unwrap_or(0);
            let dropped_bytes = s.map(|(_, s)| s.bytes_dropped).unwrap_or(0);
            let allowed_str = format!("{} ({})", allowed_pkt, format_bytes(allowed_bytes));
            let dropped_str = format!("{} ({})", dropped_pkt, format_bytes(dropped_bytes));
            println!(
                "  {:<30} {:>12} {:>12} {:>14} {:>14}",
                label, dl_str, ul_str, allowed_str, dropped_str
            );
        }
    }

    // ━━ Internal helpers ━━

    /// Resolve a target to cgroup IDs.
    ///
    /// For process names, does a DIRECT /proc walk (not identity map cache)
    /// to find all PIDs matching the name, then resolves their cgroup IDs.
    /// This avoids the "first-pid-wins" issue where aria2c shares a cgroup
    /// with alacritty — direct lookup finds aria2c's PID directly.
    fn resolve_target(&mut self, target: &Target) -> Result<Vec<u32>> {
        match target {
            Target::CgroupId(id) => Ok(vec![*id]),
            Target::ProcessName(name) => {
                // Direct /proc walk: find all PIDs whose comm matches.
                let name_lower = name.to_lowercase();
                let mut cgroup_ids = Vec::new();
                let mut seen = std::collections::HashSet::new();

                let proc_entries = match std::fs::read_dir("/proc") {
                    Ok(e) => e,
                    Err(_) => return Ok(Vec::new()),
                };

                for entry in proc_entries.flatten() {
                    let pid_str = entry.file_name();
                    let pid_str = match pid_str.to_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    let pid: u32 = match pid_str.parse() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    // Read comm.
                    let comm = match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                        Ok(s) => s.trim().to_lowercase(),
                        Err(_) => continue,
                    };

                    if comm != name_lower {
                        continue;
                    }

                    // Read cgroup path.
                    let cgroup_content =
                        match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };

                    let cgroup_path = cgroup_content
                        .lines()
                        .next()
                        .and_then(|line| line.split("::").nth(1))
                        .map(|s| s.trim().to_string());

                    let cgroup_path = match cgroup_path {
                        Some(p) if !p.is_empty() => p,
                        _ => continue,
                    };

                    // Resolve cgroup_id.
                    let full_path = format!("/sys/fs/cgroup{cgroup_path}");
                    let cgroup_id_64 =
                        match crate::ebpf::identity::resolve_cgroup_id_from_path(&full_path) {
                            Some(id) => id,
                            None => continue,
                        };

                    let cgroup_id = cgroup_id_64 as u32;
                    if seen.insert(cgroup_id) {
                        cgroup_ids.push(cgroup_id);
                    }
                }

                // Also refresh identity map for display purposes.
                self.identity.maybe_refresh();

                Ok(cgroup_ids)
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

        if let Some(bpf) = self.bpf.as_mut() {
            // Ephemeral mode: use Ebpf object.
            let map_name = format!("cgroup_policy_{}", direction.suffix());
            let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
                bpf.map_mut(&map_name)
                    .context(format!("{map_name} not found"))?,
            )
            .context(format!("Failed to access {map_name}"))?;
            map.insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("Failed to write policy: {e}"))?;
        } else {
            // Pin mode: open pinned map.
            let pin_path = self.pinned_policy_path(direction);
            let map_data = MapData::from_pin(&pin_path)
                .map_err(|e| anyhow!("pinned map {pin_path}: {e:?}"))?;
            let mut map_obj = aya::maps::Map::HashMap(map_data);
            let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(&mut map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            map.insert(cgroup_id, raw, 0)
                .map_err(|e| anyhow!("Failed to write policy: {e}"))?;
        }
        Ok(())
    }

    /// Delete a policy from BPF map. Returns Ok(true) if deleted, Ok(false) if not found.
    fn delete_policy(&mut self, cgroup_id: u32, direction: Direction) -> Result<bool> {
        if let Some(bpf) = self.bpf.as_mut() {
            let map_name = format!("cgroup_policy_{}", direction.suffix());
            let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(
                bpf.map_mut(&map_name)
                    .context(format!("{map_name} not found"))?,
            )
            .context(format!("Failed to access {map_name}"))?;
            match map.remove(&cgroup_id) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            let pin_path = self.pinned_policy_path(direction);
            let map_data = MapData::from_pin(&pin_path)
                .map_err(|e| anyhow!("pinned map {pin_path}: {e:?}"))?;
            let mut map_obj = aya::maps::Map::HashMap(map_data);
            let mut map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(&mut map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            match map.remove(&cgroup_id) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }

    /// Read all policies from a direction map.
    fn read_policies(&self, direction: Direction) -> Result<Vec<(u32, PolicyRaw)>> {
        if let Some(bpf) = self.bpf.as_ref() {
            let map_name = format!("cgroup_policy_{}", direction.suffix());
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
        } else {
            let pin_path = self.pinned_policy_path(direction);
            let map_data = MapData::from_pin(&pin_path)
                .map_err(|e| anyhow!("pinned map {pin_path}: {e:?}"))?;
            let map_obj = aya::maps::Map::HashMap(map_data);
            let map: BpfHashMap<_, u32, PolicyRaw> = BpfHashMap::try_from(&map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            let mut results = Vec::new();
            for (key, value) in map.iter().flatten() {
                results.push((key, value));
            }
            Ok(results)
        }
    }

    /// Read enforcement stats.
    fn read_stats(&self) -> Result<Vec<(u32, LimiterStatsRaw)>> {
        if let Some(bpf) = self.bpf.as_ref() {
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
        } else {
            // Pin mode: read from pinned stats map.
            let pin_path = "/sys/fs/bpf/zelynic/cgroup_limiter_stats";
            let map_data =
                MapData::from_pin(pin_path).map_err(|e| anyhow!("pinned stats map: {e:?}"))?;
            let map_obj = aya::maps::Map::HashMap(map_data);
            let map: BpfHashMap<_, u32, LimiterStatsRaw> =
                BpfHashMap::try_from(&map_obj).context("Failed to open pinned stats map")?;
            let mut results = Vec::new();
            for (key, value) in map.iter().flatten() {
                results.push((key, value));
            }
            Ok(results)
        }
    }

    /// Get the pin path for a policy map.
    fn pinned_policy_path(&self, direction: Direction) -> String {
        match direction {
            Direction::Download => "/sys/fs/bpf/zelynic/cgroup_policy_dl".to_string(),
            Direction::Upload => "/sys/fs/bpf/zelynic/cgroup_policy_ul".to_string(),
        }
    }

    /// Clear all entries from a policy map. Returns count removed.
    fn clear_policy_map(&mut self, map_name: &str) -> Result<usize> {
        let bpf = self.bpf.as_mut().context("BPF not loaded")?;

        let keys: Vec<u32> = {
            let map: BpfHashMap<_, u32, PolicyRaw> =
                BpfHashMap::try_from(bpf.map(map_name).context(format!("{map_name} not found"))?)
                    .context(format!("Failed to access {map_name}"))?;
            map.iter().flatten().map(|(k, _)| k).collect()
        };

        let count = keys.len();

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

    /// Clear all entries from a bucket map (BucketRaw).
    fn clear_bucket_map(&mut self, map_name: &str) -> Result<usize> {
        let bpf = self.bpf.as_mut().context("BPF not loaded")?;

        let keys: Vec<u32> = {
            let map: BpfHashMap<_, u32, BucketRaw> =
                BpfHashMap::try_from(bpf.map(map_name).context(format!("{map_name} not found"))?)
                    .context(format!("Failed to access {map_name}"))?;
            map.iter().flatten().map(|(k, _)| k).collect()
        };

        let count = keys.len();

        let mut map: BpfHashMap<_, u32, BucketRaw> = BpfHashMap::try_from(
            bpf.map_mut(map_name)
                .context(format!("{map_name} not found"))?,
        )
        .context(format!("Failed to access {map_name} (mut)"))?;
        for key in &keys {
            let _ = map.remove(key);
        }

        Ok(count)
    }

    /// Clear all entries from the stats map (LimiterStatsRaw).
    fn clear_stats_map(&mut self, map_name: &str) -> Result<usize> {
        let bpf = self.bpf.as_mut().context("BPF not loaded")?;

        let keys: Vec<u32> = {
            let map: BpfHashMap<_, u32, LimiterStatsRaw> =
                BpfHashMap::try_from(bpf.map(map_name).context(format!("{map_name} not found"))?)
                    .context(format!("Failed to access {map_name}"))?;
            map.iter().flatten().map(|(k, _)| k).collect()
        };

        let count = keys.len();

        let mut map: BpfHashMap<_, u32, LimiterStatsRaw> = BpfHashMap::try_from(
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
        if let Some(bpf) = self.bpf.as_ref() {
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
        } else {
            // Pin mode: read from pinned watchdog map.
            let pin_path = "/sys/fs/bpf/zelynic/watchdog_deadline";
            let map_data =
                MapData::from_pin(pin_path).map_err(|e| anyhow!("pinned watchdog map: {e:?}"))?;
            let map_obj = aya::maps::Map::Array(map_data);
            let map: BpfArray<_, u64> =
                BpfArray::try_from(&map_obj).context("Failed to open pinned watchdog map")?;

            let index: u32 = 0;
            match map.get(&index, 0) {
                Ok(deadline) => Ok(Some(deadline)),
                Err(_) => Ok(None),
            }
        }
    }

    /// Read all policies from a direction map (public for status display).
    pub fn read_policies_public(&self, direction: Direction) -> Result<Vec<(u32, PolicyRaw)>> {
        self.read_policies(direction)
    }

    /// Read enforcement stats (public for status display).
    pub fn read_stats_public(&self) -> Result<Vec<(u32, LimiterStatsRaw)>> {
        self.read_stats()
    }

    /// Borrow identity map.
    pub fn identity(&self) -> &IdentityMap {
        &self.identity
    }

    /// Force-refresh identity map. Returns number of cgroups resolved.
    pub fn refresh_identity(&mut self) -> usize {
        self.identity.refresh()
    }

    /// Pin a BPF map to the given path. Allows parent process to access maps.
    pub fn pin_map(&self, map_name: &str, pin_path: &str) -> Result<()> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        bpf.map(map_name)
            .context(format!("{map_name} not found"))?
            .pin(pin_path)
            .context(format!("Failed to pin {map_name} to {pin_path}"))?;
        Ok(())
    }

    /// Open pinned maps for read/write access (no BPF program load needed).
    /// Used by parent process to access policies managed by serve child.
    pub fn open_pinned(verbose: bool) -> Result<Self> {
        let mut limiter = Limiter {
            bpf: None, // No Ebpf object — using pinned maps directly
            cgroup_path: "/sys/fs/cgroup".to_string(),
            identity: IdentityMap::new(),
            verbose,
        };

        let resolved = limiter.identity.refresh();
        if verbose {
            eprintln!("[limiter] Identity map: {} cgroups resolved", resolved);
        }

        Ok(limiter)
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
