// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for zelynic CLI subcommands (Wolf Architecture — pure eBPF).

pub(crate) mod backend;
pub(crate) mod help;

use anyhow::Result;
use clap::Parser;

use crate::cli::{BackendCommands, Cli, Commands, EbpfCommands};

/// Top-level CLI dispatch: match parsed subcommand and delegate to focused handlers.
pub(crate) fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::Ebpf { command }) => match command {
            Some(EbpfCommands::Check) => {
                crate::ebpf::print_observer_status();
                Ok(())
            }
            Some(EbpfCommands::Observe { duration, interval }) => {
                #[cfg(feature = "ebpf")]
                {
                    handle_ebpf_observe(duration, interval)
                }
                #[cfg(not(feature = "ebpf"))]
                {
                    let _ = (duration, interval);
                    eprintln!(
                        "eBPF observer not compiled. Rebuild with: cargo build --features ebpf"
                    );
                    Err(anyhow::anyhow!("eBPF feature not enabled"))
                }
            }
            Some(EbpfCommands::Enforce {
                limits,
                stats_interval,
                duration,
                watchdog,
                allow_dangerous,
            }) => {
                #[cfg(feature = "ebpf")]
                {
                    handle_ebpf_enforce(limits, stats_interval, duration, watchdog, allow_dangerous)
                }
                #[cfg(not(feature = "ebpf"))]
                {
                    let _ = (limits, stats_interval, duration, watchdog, allow_dangerous);
                    eprintln!(
                        "eBPF limiter not compiled. Rebuild with: cargo build --features ebpf"
                    );
                    Err(anyhow::anyhow!("eBPF feature not enabled"))
                }
            }
            None => {
                crate::ebpf::print_observer_status();
                Ok(())
            }
        },

        Some(Commands::Backend { command }) => match command {
            Some(BackendCommands::Doctor(args)) => backend::handle_doctor(args.json),
            None => backend::handle_backend_info(),
        },

        Some(Commands::Completions { shell }) => backend::handle_completions(&shell),

        Some(Commands::Man) => backend::generate_man_page(),

        None => {
            Cli::parse_from(["zelynic", "--help"]);
            Ok(())
        }
    }
}

/// eBPF observer: load BPF program, attach, read counters, print summary.
#[cfg(feature = "ebpf")]
fn handle_ebpf_observe(duration: u64, interval: u64) -> Result<()> {
    use crate::ebpf::loader::Observer;
    use std::time::{Duration, Instant};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("eBPF observer requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required for eBPF observer"));
    }

    let mut observer = Observer::attach()?;

    let resolved = observer.refresh_identity();
    eprintln!(
        "[ebpf] Identity map: {} cgroup{} resolved",
        resolved,
        if resolved == 1 { "" } else { "s" }
    );
    eprintln!("[ebpf] Press Ctrl+C to stop\n");

    let start = Instant::now();
    let interval_dur = Duration::from_secs(interval);
    let mut last_print = Instant::now();

    loop {
        if last_print.elapsed() >= interval_dur {
            let summary = observer.poll_and_summarize()?;
            summary.print(observer.identity());
            last_print = Instant::now();
        }

        if duration > 0 && start.elapsed() >= Duration::from_secs(duration) {
            eprintln!("\n[ebpf] Duration reached, stopping...");
            break;
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    let summary = observer.poll_and_summarize()?;
    summary.print(observer.identity());
    observer.detach();
    Ok(())
}

/// eBPF limiter: load BPF program, apply policies, enforce rates, print stats.
#[cfg(feature = "ebpf")]
fn handle_ebpf_enforce(
    limits: Vec<String>,
    stats_interval: u64,
    duration: u64,
    watchdog: u64,
    allow_dangerous: bool,
) -> Result<()> {
    use crate::ebpf::audit::{AuditEvent, AuditLog};
    use crate::ebpf::limiter::{default_burst, parse_policy_spec, Limiter, PolicySpec};
    use std::io::{self, BufRead, Write};
    use std::time::{Duration, Instant};

    if limits.is_empty() {
        return Err(anyhow::anyhow!(
            "No policies specified. Use --limit <target>:<rate>\n\
             Example: zelynic ebpf enforce --limit firefox:1MB/s"
        ));
    }

    if !nix::unistd::geteuid().is_root() {
        eprintln!("eBPF limiter requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required for eBPF limiter"));
    }

    let watchdog = if watchdog < 5 { 5 } else { watchdog };

    let audit = AuditLog::open();
    eprintln!("[limiter] Audit log: {}", audit.path().display());

    const MIN_RATE: u64 = 1024;
    const WARN_RATE: u64 = 100_000;

    let mut specs: Vec<PolicySpec> = Vec::new();
    for (i, limit_str) in limits.iter().enumerate() {
        let (target, rate_bps) = parse_policy_spec(limit_str)?;
        let burst_bytes = default_burst(rate_bps);

        if rate_bps < MIN_RATE {
            if !allow_dangerous {
                audit.log(&AuditEvent::RateRejected {
                    target: target.clone(),
                    rate_bps,
                    reason: format!("below minimum {} B/s (use --allow-dangerous)", MIN_RATE),
                });
                return Err(anyhow::anyhow!(
                    "Rate {} B/s for '{}' is below minimum ({} B/s).\n\
                     Such a low rate will make the target unusable.\n\
                     Use --allow-dangerous to override.",
                    rate_bps,
                    target,
                    MIN_RATE
                ));
            }
            eprintln!(
                "[limiter] WARNING: rate for '{}' is below minimum ({} B/s) — overriding with --allow-dangerous",
                target, rate_bps
            );
        }

        eprintln!(
            "[limiter] Parsed policy #{}: {} → {}/s (burst: {})",
            i + 1,
            target,
            format_burst(rate_bps),
            format_burst(burst_bytes)
        );

        if rate_bps < WARN_RATE && !allow_dangerous {
            eprintln!(
                "\n  ⚠ WARNING: Limiting '{}' to {}/s may make it unusable for normal browsing.",
                target,
                format_burst(rate_bps)
            );
            eprint!("  Continue? [y/N] ");
            let _ = io::stderr().flush();
            let mut input = String::new();
            if io::stdin().lock().read_line(&mut input).is_err() {
                eprintln!("\n[limiter] Could not read input. Aborting.");
                return Ok(());
            }
            if !input.trim().eq_ignore_ascii_case("y") {
                eprintln!("[limiter] Aborted by user.");
                return Ok(());
            }
        }

        specs.push(PolicySpec {
            target,
            rate_bps,
            burst_bytes,
        });
    }

    let mut limiter = Limiter::attach()?;

    limiter.refresh_watchdog(watchdog)?;
    eprintln!("[limiter] Watchdog armed: {}s timeout", watchdog);

    let applied = limiter.apply_policies(&specs)?;

    audit.log(&AuditEvent::EnforceStart {
        policy_count: applied,
    });

    if applied == 0 {
        eprintln!("[limiter] No policies could be applied. Exiting.");
        limiter.detach();
        return Ok(());
    }

    eprintln!(
        "[limiter] {} polic{} applied. Enforcing.\n",
        applied,
        if applied == 1 { "y" } else { "ies" }
    );
    eprintln!(
        "[limiter] Safety: if zelynic crashes, BPF auto-disables in {}s",
        watchdog
    );
    eprintln!("[limiter] Press Ctrl+C to stop\n");

    let start = Instant::now();
    let stats_dur = if stats_interval > 0 {
        Duration::from_secs(stats_interval)
    } else {
        Duration::from_secs(u64::MAX / 2)
    };
    let mut last_print = Instant::now();
    let mut last_watchdog_log = Instant::now();

    loop {
        if let Err(e) = limiter.refresh_watchdog(watchdog) {
            eprintln!("[limiter] WARNING: watchdog refresh failed: {e}");
        }

        if last_print.elapsed() >= stats_dur {
            limiter.print_stats();
            limiter.print_watchdog_status();
            last_print = Instant::now();
        }

        if last_watchdog_log.elapsed() >= Duration::from_secs(5) {
            if limiter.read_watchdog().is_ok() {
                audit.log(&AuditEvent::WatchdogRefresh {
                    remaining_secs: watchdog,
                });
            }
            last_watchdog_log = Instant::now();
        }

        if duration > 0 && start.elapsed() >= Duration::from_secs(duration) {
            eprintln!("\n[limiter] Duration reached, stopping...");
            audit.log(&AuditEvent::EnforceStop {
                reason: "duration reached".to_string(),
            });
            break;
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    limiter.print_stats();
    limiter.print_watchdog_status();
    limiter.detach();
    Ok(())
}

#[cfg(feature = "ebpf")]
fn format_burst(bytes: u64) -> String {
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
