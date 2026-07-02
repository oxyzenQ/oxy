// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Help text for `zelynic --help-all`.

use colored::Colorize;

/// Print comprehensive help with all commands and examples.
pub(crate) fn print_help_all() {
    println!(
        "{}",
        "━━━ zelynic — Pure eBPF Network Rate Limiter ━━━".bold()
    );
    println!();
    println!("Wolf Architecture: single hooking layer (eBPF), no tc/nft/systemd-wrapper.");
    println!("Requires kernel 5.13+ (cgroup v2 + cgroup.id file).");
    println!();
    println!("{}", "Commands:".cyan().bold());
    println!();
    println!(
        "  {} — Real-time traffic observation (read-only)",
        "zelynic ebpf observe".green()
    );
    println!("    sudo zelynic ebpf observe --interval 5");
    println!("    sudo zelynic ebpf observe --duration 60 --interval 2");
    println!();
    println!(
        "  {} — Enforce per-cgroup rate limits",
        "zelynic ebpf enforce".green()
    );
    println!("    sudo zelynic ebpf enforce --limit firefox:1MB/s");
    println!("    sudo zelynic ebpf enforce --limit brave:500KB/s --limit unbound:100KB/s");
    println!(
        "    sudo zelynic ebpf enforce --limit firefox:1MB/s --watchdog 60 --stats-interval 5"
    );
    println!();
    println!("  {} — Check eBPF support", "zelynic ebpf check".green());
    println!();
    println!(
        "  {} — Show backend capabilities",
        "zelynic backend".green()
    );
    println!(
        "  {} — Detailed capability diagnostics",
        "zelynic backend doctor".green()
    );
    println!(
        "  {} — Generate shell completions",
        "zelynic completions <shell>".green()
    );
    println!("  {} — Generate man page", "zelynic man".green());
    println!();
    println!("{}", "Rate formats:".cyan().bold());
    println!("  500B/s    1KB/s    500KB/s    1MB/s    1GB/s");
    println!("  (case-insensitive, plain numbers = bytes/second)");
    println!();
    println!("{}", "Target formats:".cyan().bold());
    println!("  <cgroup_id>     e.g., 73386");
    println!("  <process_name>  e.g., firefox (resolves all matching cgroups)");
    println!();
    println!("{}", "Safety:".cyan().bold());
    println!("  • Watchdog: BPF auto-disables if zelynic crashes (default 30s)");
    println!("  • Min-rate guard: rejects < 1 KB/s (use --allow-dangerous)");
    println!("  • Audit log: ~/.local/share/zelynic/audit.jsonl");
    println!("  • Fail-safe: BPF returns allow on any error path");
    println!();
    println!("{}", "Examples:".cyan().bold());
    println!("  # Observe traffic for 30 seconds");
    println!("  sudo zelynic ebpf observe --duration 30");
    println!();
    println!("  # Limit Firefox to 1 MB/s download+upload");
    println!("  sudo zelynic ebpf enforce --limit firefox:1MB/s");
    println!();
    println!("  # Limit multiple processes, 10s watchdog");
    println!("  sudo zelynic ebpf enforce \\");
    println!("    --limit firefox:1MB/s \\");
    println!("    --limit unbound:100KB/s \\");
    println!("    --watchdog 10");
}
