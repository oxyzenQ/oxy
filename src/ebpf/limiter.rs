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
    Ebpf, EbpfLoader,
};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;

use crate::ebpf::bpf_syscall::{
    create_and_pin_link, kernel_supports_bpf_link, BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS,
};
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter_types::{
    default_burst, find_bpf_object, monotonic_ns, terminal_width, BucketRaw, BPF_OBJECT_PATH,
    SCHEMA_VERSION_EXPECTED,
};

// Re-export public types/functions for external use.
pub use crate::ebpf::limiter_types::{
    format_bytes, format_rate, parse_rate, parse_time_duration, validate_rate, Direction,
    LimiterStatsRaw, PolicyRaw, RateSpec, Target, MAX_RATE, MIN_RATE,
};

pub use crate::ebpf::pin::{
    pin_dir_has_files, read_pinned_schema_version, unpin_all, PIN_DIR, PIN_LINK_DL, PIN_LINK_UL,
    PIN_MAP_POLICY_DL, PIN_MAP_POLICY_UL, PIN_MAP_SCHEMA_VERSION, PIN_MAP_STATS, PIN_MAP_WATCHDOG,
    PIN_PROG_DL, PIN_PROG_UL,
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
    /// Programs AND links are pinned to /sys/fs/bpf/zelynic/ so they survive process exit.
    pub fn attach(verbose: bool) -> Result<()> {
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        // Check if ALL pins exist (fully operational from previous run).
        let all_pinned = PathBuf::from(PIN_PROG_DL).exists() && PathBuf::from(PIN_PROG_UL).exists();

        if all_pinned {
            // Check schema version. If mismatch (e.g. upgraded from v1 to v2),
            // clean up + reload to avoid struct layout incompatibility.
            match read_pinned_schema_version() {
                Some(v) if v == SCHEMA_VERSION_EXPECTED => {
                    if verbose {
                        eprintln!(
                            "[limiter] BPF programs + links already pinned (schema v{v}) — reusing"
                        );
                    }
                    return Ok(());
                }
                Some(v) => {
                    if verbose {
                        eprintln!(
                            "[limiter] Schema version mismatch: pinned v{v} ≠ expected v{SCHEMA_VERSION_EXPECTED} — reloading"
                        );
                    }
                    unpin_all()?;
                }
                None => {
                    if verbose {
                        eprintln!("[limiter] Schema version map missing — reloading");
                    }
                    unpin_all()?;
                }
            }
        } else {
            // If SOME pins exist but not all → stale state from old version or
            // crashed run. Clean up everything before reloading.
            if pin_dir_has_files() {
                if verbose {
                    eprintln!("[limiter] Stale pin files detected — cleaning up");
                }
                unpin_all()?;
            }
        }

        let obj_path = find_bpf_object()?;
        if verbose {
            eprintln!("[limiter] Loading BPF object from {}", obj_path.display());
        }
        let obj_data = std::fs::read(&obj_path)
            .context(format!("Failed to read BPF object: {}", obj_path.display()))?;

        // Create pin directory BEFORE load so maps with LIBBPF_PIN_BY_NAME
        // can be auto-pinned by EbpfLoader.
        std::fs::create_dir_all(PIN_DIR)?;

        // Use EbpfLoader with map_pin_path so all maps declared with
        // __uint(pinning, LIBBPF_PIN_BY_NAME) in limiter.bpf.c are auto-pinned
        // to /sys/fs/bpf/zelynic/<map_name>. This is what makes policies
        // persist across zelynic invocations — without it, maps vanish when
        // the Ebpf object is dropped and open_pinned() hits ENOENT.
        let mut bpf = EbpfLoader::new()
            .map_pin_path(PIN_DIR)
            .load(&obj_data)
            .context("Failed to load BPF object")?;

        // Write schema version to the pinned schema_version map.
        // This enables future migrations: if the pinned version doesn't match
        // SCHEMA_VERSION_EXPECTED, attach() cleans up + reloads.
        {
            let mut schema_map: BpfArray<_, u32> = BpfArray::try_from(
                bpf.map_mut("schema_version")
                    .context("schema_version map not found")?,
            )
            .context("Failed to access schema_version map")?;
            schema_map
                .set(0, SCHEMA_VERSION_EXPECTED, 0)
                .map_err(|e| anyhow!("Failed to write schema version: {e}"))?;
        }

        // Load + pin download program (ingress).
        let dl_prog: &mut CgroupSkb = bpf
            .program_mut("enforce_dl")
            .context("BPF program 'enforce_dl' not found")?
            .try_into()?;
        dl_prog.load()?;
        dl_prog
            .pin(PIN_PROG_DL)
            .context("Failed to pin enforce_dl")?;

        // Check kernel version for bpf_link support BEFORE borrowing ul_prog.
        let supports_link = kernel_supports_bpf_link();

        if supports_link {
            // Kernel 5.7+: extract fd, then borrow ul_prog separately.
            let dl_prog_raw = dl_prog
                .fd()
                .context("Failed to get enforce_dl fd")?
                .as_fd()
                .as_raw_fd();

            // Load + pin upload program (egress).
            let ul_prog: &mut CgroupSkb = bpf
                .program_mut("enforce_ul")
                .context("BPF program 'enforce_ul' not found")?
                .try_into()?;
            ul_prog.load()?;
            ul_prog
                .pin(PIN_PROG_UL)
                .context("Failed to pin enforce_ul")?;
            let ul_prog_raw = ul_prog
                .fd()
                .context("Failed to get enforce_ul fd")?
                .as_fd()
                .as_raw_fd();

            // Create + pin bpf_links (fire-and-forget with pin).
            let cgroup_file =
                File::open(cgroup_path).context("Failed to open cgroup root directory")?;
            let cgroup_raw = cgroup_file.as_raw_fd();
            create_and_pin_link(
                dl_prog_raw,
                cgroup_raw,
                BPF_CGROUP_INET_INGRESS,
                PIN_LINK_DL,
            )
            .context("Failed to create + pin enforce_dl link")?;
            create_and_pin_link(ul_prog_raw, cgroup_raw, BPF_CGROUP_INET_EGRESS, PIN_LINK_UL)
                .context("Failed to create + pin enforce_ul link")?;
        } else {
            // Kernel < 5.7: use legacy bpf_prog_attach via Aya.
            // Attach + take ownership of link + forget (leak) so it doesn't
            // detach on drop. Programs are pinned, so they stay loaded.
            let cgroup_file =
                File::open(cgroup_path).context("Failed to open cgroup root directory")?;
            let dl_link = dl_prog
                .attach(
                    cgroup_file.try_clone()?,
                    CgroupSkbAttachType::Ingress,
                    CgroupAttachMode::default(),
                )
                .context("Failed to attach enforce_dl (legacy)")?;
            let dl_link = dl_prog.take_link(dl_link)?;
            std::mem::forget(dl_link);

            // Now borrow ul_prog (dl_prog no longer needed).
            let ul_prog: &mut CgroupSkb = bpf
                .program_mut("enforce_ul")
                .context("BPF program 'enforce_ul' not found")?
                .try_into()?;
            ul_prog.load()?;
            ul_prog
                .pin(PIN_PROG_UL)
                .context("Failed to pin enforce_ul")?;
            let ul_link = ul_prog
                .attach(
                    cgroup_file,
                    CgroupSkbAttachType::Egress,
                    CgroupAttachMode::default(),
                )
                .context("Failed to attach enforce_ul (legacy)")?;
            let ul_link = ul_prog.take_link(ul_link)?;
            std::mem::forget(ul_link);
        }

        if verbose {
            eprintln!("[limiter] Attached + pinned to {cgroup_path} (ingress + egress)");
        }

        // Drop Ebpf object — programs stay loaded because pinned, links stay
        // attached because pinned. Maps stay loaded because pinned via
        // LIBBPF_PIN_BY_NAME.
        drop(bpf);
        Ok(())
    }

    /// Check if BPF programs are already pinned (active from previous run).
    /// Programs are required. Links are optional (only on kernel 5.7+).
    pub fn is_pinned() -> bool {
        PathBuf::from(PIN_PROG_DL).exists() && PathBuf::from(PIN_PROG_UL).exists()
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
                    "[limiter] {} download → {} (shared by {} cgroups)",
                    group_label,
                    format_rate(dl_rate),
                    all_cgroup_ids.len()
                );
            }
            if let Some(ul_rate) = rates.upload {
                eprintln!(
                    "[limiter] {} upload → {} (shared by {} cgroups)",
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
        let dl = self.read_policies(Direction::Download).unwrap_or_default();
        let ul = self.read_policies(Direction::Upload).unwrap_or_default();
        let stats = self.read_stats().unwrap_or_default();
        let wd = self.read_watchdog().ok().flatten();
        crate::ebpf::display::print_status(&dl, &ul, &stats, &self.identity, wd);
    }

    /// Print status as JSON (for --print-json).
    pub fn print_status_json(&self) -> Result<()> {
        let dl = self.read_policies(Direction::Download).unwrap_or_default();
        let ul = self.read_policies(Direction::Upload).unwrap_or_default();
        let stats = self.read_stats().unwrap_or_default();
        let wd = self.read_watchdog().ok().flatten();
        crate::ebpf::display::print_status_json(&dl, &ul, &stats, &self.identity, wd)
    }

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
    pub fn delete_policy(&mut self, cgroup_id: u32, direction: Direction) -> Result<bool> {
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
            let pin_path = PIN_MAP_STATS;
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
            Direction::Download => PIN_MAP_POLICY_DL.to_string(),
            Direction::Upload => PIN_MAP_POLICY_UL.to_string(),
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
            let pin_path = PIN_MAP_WATCHDOG;
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
    ///
    /// Identity refresh is lazy — only triggered when `refresh_identity()`
    /// or `maybe_refresh_identity()` is called. This speeds up startup
    /// for write operations (strict-single etc.) that don't need identity.
    pub fn open_pinned(verbose: bool) -> Result<Self> {
        let limiter = Limiter {
            bpf: None, // No Ebpf object — using pinned maps directly
            cgroup_path: "/sys/fs/cgroup".to_string(),
            identity: IdentityMap::new(),
            verbose,
        };

        if verbose {
            eprintln!("[limiter] Opened pinned maps (identity lazy-loaded)");
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
