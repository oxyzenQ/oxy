// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Status display logic — human-readable table + JSON output.
//! Extracted from limiter.rs to keep core logic under 800 LOC.

use anyhow::Result;
use std::collections::HashMap;

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter_types::{
    format_bytes, format_rate, monotonic_ns, terminal_width, Direction, LimiterStatsRaw, PolicyRaw,
};

/// Combined policy data for display.
struct DisplayData {
    cgroup_id: u32,
    dl_bps: Option<u64>,
    ul_bps: Option<u64>,
    packets_allowed: u64,
    packets_dropped: u64,
    bytes_allowed: u64,
    bytes_dropped: u64,
}

/// Collect display data from policies + stats.
fn collect_display_data(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
) -> Vec<DisplayData> {
    let mut combined: HashMap<u32, (Option<u64>, Option<u64>)> = HashMap::new();
    for (id, p) in dl_policies {
        combined.entry(*id).or_default().0 = Some(p.rate_bps);
    }
    for (id, p) in ul_policies {
        combined.entry(*id).or_default().1 = Some(p.rate_bps);
    }

    let mut sorted: Vec<_> = combined.into_iter().collect();
    sorted.sort_by_key(|(id, _)| *id);

    sorted
        .iter()
        .map(|(cgroup_id, (dl, ul))| {
            let s = stats.iter().find(|(id, _)| id == cgroup_id);
            DisplayData {
                cgroup_id: *cgroup_id,
                dl_bps: *dl,
                ul_bps: *ul,
                packets_allowed: s.map(|(_, s)| s.packets_allowed).unwrap_or(0),
                packets_dropped: s.map(|(_, s)| s.packets_dropped).unwrap_or(0),
                bytes_allowed: s.map(|(_, s)| s.bytes_allowed).unwrap_or(0),
                bytes_dropped: s.map(|(_, s)| s.bytes_dropped).unwrap_or(0),
            }
        })
        .collect()
}

/// Print human-readable status table.
pub fn print_status(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
) {
    println!("\n━━━ zelynic Status ━━━");

    match watchdog_deadline {
        Some(0) | None => {
            println!("  Watchdog: not set (enforcing)");
        }
        Some(deadline) => {
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

    let data = collect_display_data(dl_policies, ul_policies, stats);
    if data.is_empty() {
        return;
    }

    let rows: Vec<(String, String, String, String, String)> = data
        .iter()
        .map(|d| {
            let label = identity.label(d.cgroup_id);
            let dl_str = d.dl_bps.map(format_rate).unwrap_or_else(|| "—".to_string());
            let ul_str = d.ul_bps.map(format_rate).unwrap_or_else(|| "—".to_string());
            let allowed_str = format!("{} ({})", d.packets_allowed, format_bytes(d.bytes_allowed));
            let dropped_str = format!("{} ({})", d.packets_dropped, format_bytes(d.bytes_dropped));
            (label, dl_str, ul_str, allowed_str, dropped_str)
        })
        .collect();

    let term_w = terminal_width().saturating_sub(4);
    let headers = ["CGROUP", "DOWNLOAD", "UPLOAD", "ALLOWED", "DROPPED"];

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

    let total: usize = col_widths.iter().sum::<usize>() + 4;
    if total > term_w {
        let excess = total - term_w;
        col_widths[0] = col_widths[0].saturating_sub(excess).max(10);
    }

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

    for row in &rows {
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

/// Print JSON status (for --print-json / scripting).
pub fn print_status_json(
    dl_policies: &[(u32, PolicyRaw)],
    ul_policies: &[(u32, PolicyRaw)],
    stats: &[(u32, LimiterStatsRaw)],
    identity: &IdentityMap,
    watchdog_deadline: Option<u64>,
) -> Result<()> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct LimitEntry {
        cgroup_id: u32,
        label: String,
        download_bps: Option<u64>,
        upload_bps: Option<u64>,
        packets_allowed: u64,
        packets_dropped: u64,
        bytes_allowed: u64,
        bytes_dropped: u64,
    }

    #[derive(Serialize)]
    struct StatusJson {
        watchdog: &'static str,
        active_limits: usize,
        limits: Vec<LimitEntry>,
    }

    let watchdog = match watchdog_deadline {
        Some(0) | None => "enforcing",
        Some(d) if d > monotonic_ns() => "active",
        Some(_) => "expired",
    };

    let data = collect_display_data(dl_policies, ul_policies, stats);

    let limits: Vec<LimitEntry> = data
        .iter()
        .map(|d| LimitEntry {
            cgroup_id: d.cgroup_id,
            label: identity.label(d.cgroup_id),
            download_bps: d.dl_bps,
            upload_bps: d.ul_bps,
            packets_allowed: d.packets_allowed,
            packets_dropped: d.packets_dropped,
            bytes_allowed: d.bytes_allowed,
            bytes_dropped: d.bytes_dropped,
        })
        .collect();

    let status = StatusJson {
        watchdog,
        active_limits: limits.len(),
        limits,
    };

    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}
