// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Help text for `zelynic --help-all`.

use colored::Colorize;

/// Print comprehensive help with all commands and examples.
pub(crate) fn print_help_all() {
    println!(
        "{}",
        "━━━ zelynic — Per-app Network Rate Limiter ━━━".bold()
    );
    println!();
    println!("Limit any app's download/upload speed using eBPF.");
    println!("Pure kernel enforcement — no tc, no nft. Requires kernel 5.13+ and root.");
    println!();
    println!("{}", "Commands:".cyan().bold());
    println!();
    println!(
        "  {} — Limit a single app",
        "zelynic strict-single <target> -d <rate> [-up <rate>]".green()
    );
    println!("    sudo zelynic strict-single brave -d 100KB/s");
    println!("    sudo zelynic strict-single firefox -d 1MB/s -up 500KB/s");
    println!("    sudo zelynic strict-single 73386 -d 100KB/s --watchdog 60");
    println!();
    println!(
        "  {} — Limit multiple apps sharing one rate (group limit)",
        "zelynic strict-multi <a:b:c> -d <rate> [-up <rate>]".green()
    );
    println!("    sudo zelynic strict-multi brave:curl:pacman -d 1MB/s");
    println!("    sudo zelynic strict-multi brave:firefox -d 1MB/s -up 1MB/s");
    println!("    (all apps collectively share the rate — if one downloads at full");
    println!("     rate, others get nothing)");
    println!();
    println!(
        "  {} — Remove limit from one app",
        "zelynic unstrict <target>".green()
    );
    println!("    zelynic unstrict brave");
    println!();
    println!(
        "  {} — Remove ALL limits (emergency reset)",
        "zelynic unstrict-all".green()
    );
    println!();
    println!(
        "  {} — Show active limits + watchdog status",
        "zelynic status".green()
    );
    println!(
        "  {} — List apps with cgroup IDs",
        "zelynic list-apps".green()
    );
    println!(
        "  {} — Real-time traffic monitor (read-only)",
        "zelynic observe".green()
    );
    println!("  {} — Check eBPF support", "zelynic doctor".green());
    println!();
    println!("{}", "Global flags:".cyan().bold());
    println!("  -v, --verbose     Debug output");
    println!("  --print-json      JSON output (where applicable)");
    println!("  --no-color        Disable colored output");
    println!();
    println!("{}", "Rate formats:".cyan().bold());
    println!("  500B/s    1KB/s    500KB/s    1MB/s    1GB/s");
    println!("  Min: 1KB/s    Max: 1GB/s    (case-insensitive)");
    println!();
    println!("{}", "Target formats:".cyan().bold());
    println!("  <process_name>  e.g., brave, firefox, curl");
    println!("  <cgroup_id>     e.g., 73386 (use 'zelynic list-apps' to find)");
    println!();
    println!("{}", "Safety:".cyan().bold());
    println!("  • Watchdog: BPF auto-disables if zelynic crashes (default 30s)");
    println!("  • Min-rate guard: rejects < 1KB/s (use --allow-dangerous)");
    println!("  • Fail-safe: BPF returns allow on any error path");
    println!();
    println!("{}", "Examples:".cyan().bold());
    println!("  # Limit brave to 100KB/s download");
    println!("  sudo zelynic strict-single brave -d 100KB/s");
    println!();
    println!("  # Limit download tools to share 1MB/s total");
    println!("  sudo zelynic strict-multi curl:pacman:aria2c -d 1MB/s");
    println!();
    println!("  # Limit firefox both directions, 60s watchdog");
    println!("  sudo zelynic strict-single firefox -d 1MB/s -up 500KB/s --watchdog 60");
    println!();
    println!("  # Check what's limited");
    println!("  sudo zelynic status");
    println!();
    println!("  # Emergency: remove all limits");
    println!("  sudo zelynic unstrict-all");
}
