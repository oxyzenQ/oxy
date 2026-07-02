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
    /// Previous stats for delta calculation.
    prev_stats: std::collections::HashMap<u32, CgroupStatsRaw>,
    /// Wolf Architecture Layer 2: cgroup ID → process identity resolver.
    /// Refreshed lazily via `maybe_refresh()` before each summary print.
    identity: IdentityMap,
}

impl Observer {
    pub fn attach() -> Result<Self> {
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        let obj_path = find_bpf_object()?;
        eprintln!("[ebpf] Loading BPF object from {}", obj_path.display());
        let obj_data = std::fs::read(&obj_path)
            .context(format!("Failed to read BPF object: {}", obj_path.display()))?;

        let mut bpf = Ebpf::load(&obj_data).context("Failed to load BPF object")?;

        let program: &mut CgroupSkb = bpf
            .program_mut("observe_egress")
            .context("BPF program 'observe_egress' not found")?
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

        // link_id is stored internally by aya — program stays attached
        // as long as the Ebpf object is alive
        eprintln!("[ebpf] Observer attached to {cgroup_path}");
        eprintln!("[ebpf] Monitoring egress traffic for all processes");

        Ok(Observer {
            bpf: Some(bpf),
            cgroup_path: cgroup_path.to_string(),
            prev_stats: std::collections::HashMap::new(),
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

    /// Read cgroup_counters map directly. Returns (cgroup_id, stats) pairs.
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

    /// Read counters, compute deltas, return summary.
    pub fn poll_and_summarize(&mut self) -> Result<CounterSummary> {
        let current = self.read_counters()?;
        let mut summary = CounterSummary::default();

        for (cgroup_id, stats) in &current {
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
                });
            }
        }

        // Update prev_stats
        self.prev_stats.clear();
        for (cgroup_id, stats) in current {
            self.prev_stats.insert(cgroup_id, stats);
        }

        // Refresh identity map if stale — ensures labels stay current
        // with process churn without paying the /proc walk cost every poll.
        self.maybe_refresh_identity();

        Ok(summary)
    }

    pub fn detach(&mut self) {
        self.bpf = None;
        eprintln!("[ebpf] Observer detached from {}", self.cgroup_path);
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        if self.bpf.is_some() {
            eprintln!("[ebpf] Cleaning up BPF programs");
            self.bpf = None;
        }
    }
}

#[derive(Debug, Default)]
pub struct CounterSummary {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub cgroups: Vec<CgroupDelta>,
}

#[derive(Debug, Clone)]
pub struct CgroupDelta {
    pub cgroup_id: u32,
    pub packets: u64,
    pub bytes: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
}

impl CounterSummary {
    /// Print summary using identity map for human-readable cgroup labels.
    ///
    /// Wolf Architecture Layer 3: Aggregation enriches raw counters with
    /// identity (Layer 2) before presentation (Layer 4).
    pub fn print(&self, identity: &IdentityMap) {
        if self.total_packets == 0 {
            println!("\n  (no traffic since last check)");
            return;
        }

        println!("\n━━━ eBPF Traffic Summary ━━━");
        println!("  Packets:  {}", self.total_packets);
        println!("  Bytes:    {}", format_bytes(self.total_bytes));
        println!("  Cgroups:  {}", self.cgroups.len());
        if !identity.is_empty() {
            println!("  Resolved: {} cgroup identities", identity.len());
        }
        println!();

        let mut sorted = self.cgroups.clone();
        sorted.sort_by_key(|c| std::cmp::Reverse(c.bytes));

        println!(
            "  {:<30} {:>10} {:>10} {:>12}",
            "CGROUP", "DELTA PKT", "DELTA BYTES", "TOTAL BYTES"
        );
        println!("  {}", "─".repeat(66));

        for c in sorted.iter().take(20) {
            println!(
                "  {:<30} {:>10} {:>10} {:>12}",
                identity.label(c.cgroup_id),
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
