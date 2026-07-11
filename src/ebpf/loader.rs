// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF loader — load, attach, and read cgroup counters directly.
//!
//! Simplified: no ring buffer. BPF program updates a hash map,
//! userspace reads the map directly every interval.

use anyhow::{bail, Context, Result};
use aya::{
    maps::HashMap as BpfHashMap,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf,
};
use std::fs::File;
use std::path::PathBuf;

use crate::ebpf::identity::IdentityMap;

const BPF_OBJECT_PATH: &str = "bpf/observer.bpf.o";

/// Per-cgroup stats from BPF map (must match C struct).
/// Must be Plain Old Data for aya's Pod trait.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct CgroupStatsRaw {
    pub packets: u64,
    pub bytes: u64,
    pub last_event_packet: u64,
}

unsafe impl aya::Pod for CgroupStatsRaw {}

pub struct Observer {
    bpf: Option<Ebpf>,
    cgroup_path: String,
    /// Previous egress stats for delta calculation.
    prev_stats: std::collections::HashMap<u32, CgroupStatsRaw>,
    /// Previous ingress stats for delta calculation.
    prev_stats_ingress: std::collections::HashMap<u32, CgroupStatsRaw>,
    /// Dragon Architecture Layer 2: cgroup ID → process identity resolver.
    /// Refreshed lazily via `maybe_refresh()` before each summary print.
    identity: IdentityMap,
}

impl Observer {
    pub fn attach() -> Result<Self> {
        Self::attach_quiet(false)
    }

    /// Attach with optional quiet mode (suppresses eprintln messages).
    /// Used by observe/top when running in alt-screen mode.
    pub fn attach_quiet(quiet: bool) -> Result<Self> {
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        let obj_path = find_bpf_object()?;
        if !quiet {
            eprintln!("[ebpf] Loading BPF object from {}", obj_path.display());
        }
        let obj_data = std::fs::read(&obj_path)
            .context(format!("Failed to read BPF object: {}", obj_path.display()))?;

        let mut bpf = Ebpf::load(&obj_data).context("Failed to load BPF object")?;

        let cgroup_file =
            File::open(cgroup_path).context("Failed to open cgroup root directory")?;

        // Load + attach egress observer
        let egress_prog: &mut CgroupSkb = bpf
            .program_mut("observe_egress")
            .context("BPF program 'observe_egress' not found")?
            .try_into()?;
        egress_prog.load()?;
        egress_prog
            .attach(
                cgroup_file.try_clone()?,
                CgroupSkbAttachType::Egress,
                CgroupAttachMode::default(),
            )
            .context("Failed to attach observe_egress")?;

        // Load + attach ingress observer
        let ingress_prog: &mut CgroupSkb = bpf
            .program_mut("observe_ingress")
            .context("BPF program 'observe_ingress' not found")?
            .try_into()?;
        ingress_prog.load()?;
        ingress_prog
            .attach(
                cgroup_file,
                CgroupSkbAttachType::Ingress,
                CgroupAttachMode::default(),
            )
            .context("Failed to attach observe_ingress")?;

        if !quiet {
            eprintln!("[ebpf] Observer attached to {cgroup_path} (egress + ingress)");
            eprintln!("[ebpf] Monitoring traffic for all processes");
        }

        Ok(Observer {
            bpf: Some(bpf),
            cgroup_path: cgroup_path.to_string(),
            prev_stats: std::collections::HashMap::new(),
            prev_stats_ingress: std::collections::HashMap::new(),
            identity: IdentityMap::new(),
        })
    }

    /// Borrow the identity map (read-only) for label rendering.
    pub fn identity(&self) -> &IdentityMap {
        &self.identity
    }

    /// Force-refresh the identity map. Returns the number of cgroups resolved.
    pub fn refresh_identity(&mut self) -> usize {
        self.identity.refresh()
    }

    /// Lazily refresh the identity map if its TTL has elapsed.
    /// Call this before printing a summary to ensure labels are fresh.
    pub fn maybe_refresh_identity(&mut self) -> bool {
        self.identity.maybe_refresh()
    }

    /// Read egress cgroup_counters map. Returns (cgroup_id, stats) pairs.
    pub fn read_counters(&self) -> Result<Vec<(u32, CgroupStatsRaw)>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, CgroupStatsRaw> =
            BpfHashMap::try_from(bpf.map("cgroup_counters").context("map not found")?)
                .context("Failed to access cgroup_counters map")?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read ingress cgroup_counters_ingress map. Returns (cgroup_id, stats) pairs.
    pub fn read_counters_ingress(&self) -> Result<Vec<(u32, CgroupStatsRaw)>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, CgroupStatsRaw> = BpfHashMap::try_from(
            bpf.map("cgroup_counters_ingress")
                .context("map not found")?,
        )
        .context("Failed to access cgroup_counters_ingress map")?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read counters (egress + ingress), compute deltas, return summary.
    pub fn poll_and_summarize(&mut self) -> Result<CounterSummary> {
        let current_egress = self.read_counters()?;
        let current_ingress = self.read_counters_ingress().unwrap_or_default();
        let mut summary = CounterSummary::default();

        // Process egress (upload) deltas
        for (cgroup_id, stats) in &current_egress {
            let prev = self.prev_stats.get(cgroup_id).copied().unwrap_or_default();
            let delta_packets = stats.packets.saturating_sub(prev.packets);
            let delta_bytes = stats.bytes.saturating_sub(prev.bytes);

            if delta_packets > 0 {
                summary.total_packets += delta_packets;
                summary.total_bytes += delta_bytes;
                summary.cgroups.push(CgroupDelta {
                    cgroup_id: *cgroup_id,
                    packets: delta_packets,
                    bytes: delta_bytes,
                    total_packets: stats.packets,
                    total_bytes: stats.bytes,
                    ingress_packets: 0,
                    ingress_bytes: 0,
                });
            }
        }

        // Merge ingress (download) deltas into existing cgroups
        for (cgroup_id, stats) in &current_ingress {
            let prev = self
                .prev_stats_ingress
                .get(cgroup_id)
                .copied()
                .unwrap_or_default();
            let delta_packets = stats.packets.saturating_sub(prev.packets);
            let delta_bytes = stats.bytes.saturating_sub(prev.bytes);

            if delta_packets > 0 {
                summary.total_ingress_packets += delta_packets;
                summary.total_ingress_bytes += delta_bytes;

                if let Some(entry) = summary
                    .cgroups
                    .iter_mut()
                    .find(|c| c.cgroup_id == *cgroup_id)
                {
                    entry.ingress_packets = delta_packets;
                    entry.ingress_bytes = delta_bytes;
                } else {
                    summary.cgroups.push(CgroupDelta {
                        cgroup_id: *cgroup_id,
                        packets: 0,
                        bytes: 0,
                        total_packets: 0,
                        total_bytes: 0,
                        ingress_packets: delta_packets,
                        ingress_bytes: delta_bytes,
                    });
                }
            }
        }

        // Update prev_stats
        self.prev_stats.clear();
        for (cgroup_id, stats) in current_egress {
            self.prev_stats.insert(cgroup_id, stats);
        }
        self.prev_stats_ingress.clear();
        for (cgroup_id, stats) in current_ingress {
            self.prev_stats_ingress.insert(cgroup_id, stats);
        }

        // Refresh identity map if stale
        self.maybe_refresh_identity();

        Ok(summary)
    }

    pub fn detach(&mut self) {
        self.bpf = None;
    }

    pub fn detach_verbose(&mut self) {
        self.bpf = None;
        eprintln!("[ebpf] Observer detached from {}", self.cgroup_path);
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.bpf = None;
    }
}

#[derive(Debug, Default)]
pub struct CounterSummary {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_ingress_packets: u64,
    pub total_ingress_bytes: u64,
    pub cgroups: Vec<CgroupDelta>,
}

#[derive(Debug, Clone)]
pub struct CgroupDelta {
    pub cgroup_id: u32,
    pub packets: u64,
    pub bytes: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub ingress_packets: u64,
    pub ingress_bytes: u64,
}

impl CounterSummary {
    /// Print summary using identity map for human-readable cgroup labels.
    ///
    /// Dragon Architecture Layer 3: Aggregation enriches raw counters with
    /// identity (Layer 2) before presentation (Layer 4).
    pub fn print(&self, identity: &IdentityMap) {
        if self.total_packets == 0 && self.total_ingress_packets == 0 {
            println!("\n  (no traffic since last check)");
            return;
        }

        println!("\n━━━ eBPF Traffic Summary ━━━");
        println!(
            "  Egress (upload):  {} packets, {}",
            self.total_packets,
            format_bytes(self.total_bytes)
        );
        println!(
            "  Ingress (download): {} packets, {}",
            self.total_ingress_packets,
            format_bytes(self.total_ingress_bytes)
        );
        println!("  Cgroups:  {}", self.cgroups.len());
        if !identity.is_empty() {
            println!("  Resolved: {} cgroup identities", identity.len());
        }
        println!();

        let mut sorted = self.cgroups.clone();
        sorted.sort_by_key(|c| std::cmp::Reverse(c.bytes + c.ingress_bytes));

        println!(
            "  {:<30} {:>12} {:>12}",
            "CGROUP", "EGRESS (UL)", "INGRESS (DL)"
        );
        println!("  {}", "─".repeat(58));

        for c in sorted.iter().take(20) {
            let ul_str = if c.bytes > 0 {
                format!("{} ({})", c.packets, format_bytes(c.bytes))
            } else {
                "—".to_string()
            };
            let dl_str = if c.ingress_bytes > 0 {
                format!("{} ({})", c.ingress_packets, format_bytes(c.ingress_bytes))
            } else {
                "—".to_string()
            };
            println!(
                "  {:<30} {:>12} {:>12}",
                identity.label(c.cgroup_id),
                ul_str,
                dl_str,
            );
        }
    }

    /// Print summary filtered to a single cgroup ID.
    pub fn print_filtered(&self, identity: &IdentityMap, cgroup_id: u32) {
        let filtered: Vec<_> = self
            .cgroups
            .iter()
            .filter(|c| c.cgroup_id == cgroup_id)
            .collect();

        if filtered.is_empty() {
            println!("\n  (no traffic for cgroup {cgroup_id} since last check)");
            return;
        }

        println!("\n━━━ eBPF Traffic (cgroup {cgroup_id}) ━━━");
        let label = identity.label(cgroup_id);
        println!("  Label:    {label}");
        println!("  Cgroups:  {}", filtered.len());
        println!();

        println!(
            "  {:<30} {:>10} {:>10} {:>12}",
            "CGROUP", "DELTA PKT", "DELTA BYTES", "TOTAL BYTES"
        );
        println!("  {}", "─".repeat(66));

        for c in &filtered {
            println!(
                "  {:<30} {:>10} {:>10} {:>12}",
                label,
                c.packets,
                format_bytes(c.bytes),
                format_bytes(c.total_bytes),
            );
        }
    }

    /// Print summary with verbose labels (includes cgroup path).
    pub fn print_verbose(&self, identity: &IdentityMap) {
        if self.total_packets == 0 {
            println!("\n  (no traffic since last check)");
            return;
        }

        println!("\n━━━ eBPF Traffic Summary (verbose) ━━━");
        println!("  Packets:  {}", self.total_packets);
        println!("  Bytes:    {}", format_bytes(self.total_bytes));
        println!("  Cgroups:  {}", self.cgroups.len());
        if !identity.is_empty() {
            println!("  Resolved: {} cgroup identities", identity.len());
        }
        println!();

        let mut sorted = self.cgroups.clone();
        sorted.sort_by_key(|c| std::cmp::Reverse(c.bytes));

        for c in sorted.iter().take(20) {
            println!("  {}", identity.label_verbose(c.cgroup_id));
            println!(
                "    delta: {} pkt / {}   total: {}",
                c.packets,
                format_bytes(c.bytes),
                format_bytes(c.total_bytes)
            );
        }
    }
}

fn find_bpf_object() -> Result<PathBuf> {
    let candidates = [
        PathBuf::from(BPF_OBJECT_PATH),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BPF_OBJECT_PATH),
        PathBuf::from("/usr/lib/zelynic/observer.bpf.o"),
        PathBuf::from("/usr/local/lib/zelynic/observer.bpf.o"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    bail!(
        "BPF object file not found. Compile with:\n  \
         clang -O2 -g -target bpf -c bpf/observer.bpf.c -o bpf/observer.bpf.o\n  \
         Searched: {:?}",
        candidates
    )
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
