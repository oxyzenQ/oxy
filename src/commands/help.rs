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
        "zelynic strict-single <target> [rate] [-d <rate>] [-u <rate>]".green()
    );
    println!("    sudo zelynic strict-single brave 100kb              # both dl+ul = 100kb");
    println!("    sudo zelynic strict-single brave -d 100kb           # download only");
    println!("    sudo zelynic strict-single brave -u 500kb           # upload only");
    println!("    sudo zelynic strict-single firefox -d 1mb -u 500kb  # both, different rates");
    println!();
    println!(
        "  {} — Limit multiple apps sharing one rate (group limit)",
        "zelynic strict-multi <a:b:c> [rate] [-d <rate>] [-u <rate>]".green()
    );
    println!("    sudo zelynic strict-multi brave:curl:pacman 1mb");
    println!("    sudo zelynic strict-multi brave:firefox -d 1mb -u 500kb");
    println!("    (all apps collectively share the rate — if one downloads at full");
    println!("     rate, others get nothing)");
    println!();
    println!(
        "  {} — Limit ALL user apps from list-apps",
        "zelynic limit-all [rate] [-d <rate>] [-u <rate>]".green()
    );
    println!("    sudo zelynic limit-all 500kb              # limit all user apps");
    println!("    sudo zelynic limit-all -d 1mb -u 500kb    # per-direction");
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
        "  {} — Block an app from the internet entirely",
        "zelynic block-single <target>".green()
    );
    println!("    sudo zelynic block-single brave");
    println!(
        "  {} — Block multiple apps from internet",
        "zelynic block-multi <a:b:c>".green()
    );
    println!("    sudo zelynic block-multi brave:curl:pacman");
    println!(
        "  {} — Block ALL user apps from internet",
        "zelynic block-all".green()
    );
    println!("    sudo zelynic block-all                   # all user apps");
    println!("    sudo zelynic block-all --force            # include system apps");
    println!(
        "  {} — Unblock an app (restore internet access)",
        "zelynic unblock <target>".green()
    );
    println!("    zelynic unblock brave");
    println!();
    println!(
        "  {} — Recover from crash (clean orphaned pins)",
        "zelynic recover".green()
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
        "  {} — Real-time traffic monitor (box mode, in-place)",
        "zelynic observe [--live <dur>] [--cgroup <id>]".green()
    );
    println!("    sudo zelynic observe                    # live forever, q/ESC to quit");
    println!("    sudo zelynic observe --live 3m           # live for 3 minutes");
    println!("    sudo zelynic observe --cgroup 8066       # filter to one cgroup");
    println!(
        "  {} — Find top bandwidth consumers",
        "zelynic top [--duration <dur>] [--live <dur>] [--limit N]".green()
    );
    println!("    sudo zelynic top                        # 10s snapshot, top 10");
    println!("    sudo zelynic top --duration 30s         # 30s snapshot");
    println!("    sudo zelynic top --live 5m              # live box mode for 5 min");
    println!("    sudo zelynic top --live 0               # live forever (catches bursty apps)");
    println!("  {} — Check eBPF support", "zelynic doctor".green());
    println!();
    println!("{}", "Global flags:".cyan().bold());
    println!("  -v, --verbose     Debug output");
    println!("  --print-json      JSON output (where applicable)");
    println!("  --no-color        Disable colored output");
    println!();
    println!("{}", "Rate formats:".cyan().bold());
    println!("  500b    1kb    500kb    1mb    1gb    100gb    (lowercase only)");
    println!("  Min: 1kb (1024 b/s)    Max: 100gb (100,000,000,000 b/s)");
    println!("  Both bounds overridable with --allow-dangerous");
    println!();
    println!("{}", "Target formats:".cyan().bold());
    println!("  <process_name>  e.g., brave, firefox, curl");
    println!("  <cgroup_id>     e.g., 73386 (use 'zelynic list-apps' to find)");
    println!();
    println!("{}", "Safety:".cyan().bold());
    println!("  • Min-rate guard: rejects < 1kb (use --allow-dangerous)");
    println!("  • Dangerous target warning: 53 system processes blocked by default");
    println!("    (use --force to override)");
    println!("  • Fail-safe: BPF returns allow on any error path");
    println!();
    println!("{}", "Examples:".cyan().bold());
    println!("  # Limit brave to 100kb/s (both download + upload)");
    println!("  sudo zelynic strict-single brave 100kb");
    println!();
    println!("  # Limit brave download only to 100kb/s");
    println!("  sudo zelynic strict-single brave -d 100kb");
    println!();
    println!("  # Limit download tools to share 1mb/s total");
    println!("  sudo zelynic strict-multi curl:pacman:aria2c 1mb");
    println!();
    println!("  # Limit firefox both directions, different rates");
    println!("  sudo zelynic strict-single firefox -d 1mb -u 500kb");
    println!();
    println!("  # Check what's limited");
    println!("  sudo zelynic status");
    println!();
    println!("  # JSON output (for scripts)");
    println!("  sudo zelynic status --print-json | jq '.limits[]'");
    println!();
    println!("  # Monitor traffic in box mode (UL + DL)");
    println!("  sudo zelynic observe --live 5m");
    println!();
    println!("  # Find what's eating your bandwidth");
    println!("  sudo zelynic top --live 0");
    println!();
    println!("  # Recover from crash (clean orphaned pins)");
    println!("  sudo zelynic recover");
    println!();
    println!("  # Emergency: remove all limits");
    println!("  sudo zelynic unstrict-all");
}
