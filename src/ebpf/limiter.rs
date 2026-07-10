// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF limiter — token-bucket rate enforcement per cgroup or per group.
//!
//! Types and helpers in `limiter_types.rs`. This file contains the
//! `Limiter` struct and its implementation only.

use anyhow::{anyhow, bail, Context, Result};
use aya::{
    maps::{Array as BpfArray, HashMap as BpfHashMap, MapData},
    programs::CgroupSkb,
    Ebpf, EbpfLoader,
};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::path::PathBuf;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter_types::{
    default_burst, find_bpf_object, monotonic_ns, terminal_width, BucketRaw, BPF_OBJECT_PATH,
};

// Re-export public types/functions for external use.
pub use crate::ebpf::limiter_types::{
    format_bytes, format_rate, parse_rate, validate_rate, Direction, LimiterStatsRaw, PolicyRaw,
    RateSpec, Target, MAX_RATE, MIN_RATE,
};

// ━━ Raw BPF syscall helpers ━━
//
// Aya 0.13's CgroupSkb::attach() creates a bpf_link (fd-based) on kernel 5.7+.
// When the Ebpf object is dropped, Aya closes the link fd → link detached →
// BPF never executes. Aya does NOT expose a public API to pin CgroupSkb links
// (CgroupSkbLinkInner is pub(crate)). So we bypass Aya's attach and do it
// ourselves via raw bpf() syscalls:
//   1. BPF_LINK_CREATE  — creates a link fd
//   2. BPF_OBJ_PIN      — pins the link fd to bpffs so it survives process exit

/// BPF syscall command numbers (from linux/bpf.h).
const BPF_LINK_CREATE: i32 = 28;
const BPF_OBJ_PIN: i32 = 6;

/// BPF attach types for cgroup_skb (from linux/bpf.h).
const BPF_CGROUP_INET_INGRESS: u32 = 0;
const BPF_CGROUP_INET_EGRESS: u32 = 1;

/// Attribute struct for BPF_LINK_CREATE.
/// Layout must match `union bpf_attr` → `struct { prog_fd, target_fd, attach_type, flags }`.
#[repr(C)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
    // Remaining fields (target_btf_id, etc.) are zero-filled by the kernel
    // when attr_size is small. We only need the first 16 bytes for cgroup_skb.
    _pad: [u8; 40],
}

/// Attribute struct for BPF_OBJ_PIN.
#[repr(C)]
struct ObjPinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// Create a bpf_link attaching `prog_fd` to `target_fd` (cgroup fd).
/// Returns the raw link fd on success. Caller owns the fd and must close it.
fn sys_bpf_link_create(prog_fd: RawFd, target_fd: RawFd, attach_type: u32) -> Result<RawFd> {
    let attr = LinkCreateAttr {
        prog_fd: prog_fd as u32,
        target_fd: target_fd as u32,
        attach_type,
        flags: 0,
        _pad: [0u8; 40],
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_LINK_CREATE,
            &attr as *const _,
            std::mem::size_of::<LinkCreateAttr>(),
        )
    };
    if ret < 0 {
        bail!(
            "BPF_LINK_CREATE failed: {} (attach_type={attach_type})",
            std::io::Error::last_os_error()
        );
    }
    Ok(ret as RawFd)
}

/// Pin a BPF object (link or program) fd to a path on bpffs.
fn sys_bpf_obj_pin(fd: RawFd, path: &str) -> Result<()> {
    use std::ffi::CString;
    let path_c = CString::new(path).with_context(|| format!("Invalid pin path: {path}"))?;
    let attr = ObjPinAttr {
        pathname: path_c.as_ptr() as u64,
        bpf_fd: fd as u32,
        file_flags: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_PIN,
            &attr as *const _,
            std::mem::size_of::<ObjPinAttr>(),
        )
    };
    if ret < 0 {
        bail!(
            "BPF_OBJ_PIN failed for {path}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Create a bpf_link, pin it to bpffs, and close the fd.
/// The link stays attached as long as the pin file exists.
fn create_and_pin_link(
    prog_fd: RawFd,
    cgroup_fd: RawFd,
    attach_type: u32,
    link_pin_path: &str,
) -> Result<()> {
    // Remove stale pin file if it exists (from a previous crashed run).
    let _ = std::fs::remove_file(link_pin_path);

    let link_fd = sys_bpf_link_create(prog_fd, cgroup_fd, attach_type)?;
    sys_bpf_obj_pin(link_fd, link_pin_path)?;
    // Close the link fd — the pin keeps the link alive in kernel.
    unsafe { libc::close(link_fd) };
    Ok(())
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
    /// Programs AND links are pinned to /sys/fs/bpf/zelynic/ so they survive process exit.
    pub fn attach(verbose: bool) -> Result<()> {
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        // Pin paths for programs + links.
        let dl_pin = "/sys/fs/bpf/zelynic/enforce_dl";
        let ul_pin = "/sys/fs/bpf/zelynic/enforce_ul";
        let dl_link_pin = "/sys/fs/bpf/zelynic/enforce_dl_link";
        let ul_link_pin = "/sys/fs/bpf/zelynic/enforce_ul_link";

        // Check if programs already pinned (from previous run).
        if PathBuf::from(dl_pin).exists()
            && PathBuf::from(ul_pin).exists()
            && PathBuf::from(dl_link_pin).exists()
            && PathBuf::from(ul_link_pin).exists()
        {
            if verbose {
                eprintln!("[limiter] BPF programs + links already pinned — reusing");
            }
            return Ok(());
        }

        let obj_path = find_bpf_object()?;
        if verbose {
            eprintln!("[limiter] Loading BPF object from {}", obj_path.display());
        }
        let obj_data = std::fs::read(&obj_path)
            .context(format!("Failed to read BPF object: {}", obj_path.display()))?;

        // Create pin directory BEFORE load so maps with LIBBPF_PIN_BY_NAME
        // can be auto-pinned by EbpfLoader.
        std::fs::create_dir_all("/sys/fs/bpf/zelynic")?;

        // Use EbpfLoader with map_pin_path so all maps declared with
        // __uint(pinning, LIBBPF_PIN_BY_NAME) in limiter.bpf.c are auto-pinned
        // to /sys/fs/bpf/zelynic/<map_name>. This is what makes policies
        // persist across zelynic invocations — without it, maps vanish when
        // the Ebpf object is dropped and open_pinned() hits ENOENT.
        let mut bpf = EbpfLoader::new()
            .map_pin_path("/sys/fs/bpf/zelynic")
            .load(&obj_data)
            .context("Failed to load BPF object")?;

        // Load + pin download program (ingress). Do NOT call prog.attach() —
        // Aya 0.13's attach creates a bpf_link that gets detached on drop.
        // We create + pin the link ourselves via raw bpf() syscalls.
        let dl_prog: &mut CgroupSkb = bpf
            .program_mut("enforce_dl")
            .context("BPF program 'enforce_dl' not found")?
            .try_into()?;
        dl_prog.load()?;
        dl_prog.pin(dl_pin).context("Failed to pin enforce_dl")?;
        // Extract the program fd NOW — we need it after the &mut bpf borrow ends.
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
        ul_prog.pin(ul_pin).context("Failed to pin enforce_ul")?;
        let ul_prog_raw = ul_prog
            .fd()
            .context("Failed to get enforce_ul fd")?
            .as_fd()
            .as_raw_fd();

        // Open cgroup root for BPF_LINK_CREATE target_fd.
        let cgroup_file =
            File::open(cgroup_path).context("Failed to open cgroup root directory")?;
        let cgroup_raw = cgroup_file.as_raw_fd();

        // Create + pin links. The link fd is closed after pinning, but the
        // pin keeps the link alive in kernel → BPF stays attached after
        // process exit.
        create_and_pin_link(
            dl_prog_raw,
            cgroup_raw,
            BPF_CGROUP_INET_INGRESS,
            dl_link_pin,
        )
        .context("Failed to create + pin enforce_dl link")?;
        create_and_pin_link(ul_prog_raw, cgroup_raw, BPF_CGROUP_INET_EGRESS, ul_link_pin)
            .context("Failed to create + pin enforce_ul link")?;

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
    pub fn is_pinned() -> bool {
        PathBuf::from("/sys/fs/bpf/zelynic/enforce_dl").exists()
            && PathBuf::from("/sys/fs/bpf/zelynic/enforce_ul").exists()
            && PathBuf::from("/sys/fs/bpf/zelynic/enforce_dl_link").exists()
            && PathBuf::from("/sys/fs/bpf/zelynic/enforce_ul_link").exists()
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
        // deadline == 0 means "no deadline set" → BPF always enforces.
        // deadline != 0 means fail-safe timeout is active.
        match self.read_watchdog() {
            Ok(Some(0)) | Ok(None) | Err(_) => {
                println!("  Watchdog: not set (enforcing)");
            }
            Ok(Some(deadline)) => {
                let now = monotonic_ns();
                if deadline > now {
                    let remaining = (deadline - now) / 1_000_000_000;
                    println!("  Watchdog: {remaining}s remaining");
                } else {
                    println!("  Watchdog: EXPIRED (BPF is no-op)");
                }
            }
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

        // Build row data first so we can calculate column widths.
        let rows: Vec<(String, String, String, String, String)> = sorted
            .iter()
            .map(|(cgroup_id, (dl, ul))| {
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
                (label, dl_str, ul_str, allowed_str, dropped_str)
            })
            .collect();

        // Dynamic column widths based on terminal width.
        let term_w = terminal_width().saturating_sub(4); // 2 for indent + 2 margin
        let headers = ["CGROUP", "DOWNLOAD", "UPLOAD", "ALLOWED", "DROPPED"];

        // Calculate natural column widths from headers + data.
        let mut col_widths = [0usize; 5];
        for (i, h) in headers.iter().enumerate() {
            col_widths[i] = h.len();
        }
        for row in &rows {
            col_widths[0] = col_widths[0].max(row.0.chars().count());
            col_widths[1] = col_widths[1].max(row.1.len());
            col_widths[2] = col_widths[2].max(row.2.len());
            col_widths[3] = col_widths[3].max(row.3.len());
            col_widths[4] = col_widths[4].max(row.4.len());
        }

        // Total width = sum of columns + 4 spaces (separators)
        let total: usize = col_widths.iter().sum::<usize>() + 4;
        if total > term_w {
            // Shrink CGROUP column first (most flexible).
            let excess = total - term_w;
            col_widths[0] = col_widths[0].saturating_sub(excess).max(10);
        }

        // Print header
        println!(
            "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
            headers[0],
            headers[1],
            headers[2],
            headers[3],
            headers[4],
            w0 = col_widths[0],
            w1 = col_widths[1],
            w2 = col_widths[2],
            w3 = col_widths[3],
            w4 = col_widths[4]
        );
        let sep_len: usize = col_widths.iter().sum::<usize>() + 4;
        println!("  {}", "─".repeat(sep_len));

        // Print rows
        for row in &rows {
            // Truncate label if needed
            let label = if row.0.chars().count() > col_widths[0] {
                let truncated: String = row
                    .0
                    .chars()
                    .take(col_widths[0].saturating_sub(1))
                    .collect();
                format!("{truncated}…")
            } else {
                row.0.clone()
            };
            println!(
                "  {:<w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
                label,
                row.1,
                row.2,
                row.3,
                row.4,
                w0 = col_widths[0],
                w1 = col_widths[1],
                w2 = col_widths[2],
                w3 = col_widths[3],
                w4 = col_widths[4]
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
