// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for all zelynic CLI subcommands.
//!
//! This module provides the top-level dispatch that routes parsed CLI subcommands
//! to focused handler functions organized by domain. Each sub-file contains handlers
//! for a related set of commands.

pub(crate) mod backend;
pub(crate) mod help;
pub(crate) mod ledger;
pub(crate) mod monitor;
pub(crate) mod profile;
pub(crate) mod run;
pub(crate) mod strict;
pub(crate) mod strict_run_lab;
pub(crate) mod usage;
pub(crate) mod usage_delta;

use anyhow::Result;
use clap::Parser;

use crate::cli::{
    render_design_gated_message, BackendCommands, Cli, Commands, EbpfCommands, LedgerCommands,
    ProfileCommands, QosCommands,
};

/// Top-level CLI dispatch: match parsed subcommand and delegate to focused handlers.
pub(crate) fn dispatch(cli: Cli, iface_value: Option<&str>) -> Result<()> {
    match cli.command {
        Some(Commands::List {
            usage_all,
            high_to_low,
            json,
            live,
            interval,
            verbose,
        }) => monitor::handle_list(
            usage_all,
            high_to_low,
            json,
            live,
            interval,
            verbose,
            iface_value,
        ),

        Some(Commands::Strict {
            download,
            upload,
            preset,
            diagnose,
            run_lab,
            target,
        }) => {
            if run_lab {
                // Hidden experimental alias: strict --run-lab → strict-run-lab handler.
                // target contains the full child command (name + args after `--`).
                strict_run_lab::handle_strict_run_lab(
                    download,
                    upload,
                    diagnose,
                    iface_value,
                    &target,
                )
            } else {
                // Normal attach-mode strict: target must be exactly one value.
                if target.len() != 1 {
                    // Reject extra positional args in normal mode.
                    // This preserves the existing CLI contract: strict takes exactly one target.
                    let extra: Vec<&str> = target.iter().skip(1).map(|s| s.as_str()).collect();
                    return Err(anyhow::anyhow!(
                        "unexpected argument(s): {}. Usage: zelynic strict -d <rate> <TARGET>",
                        extra.join(" ")
                    ));
                }
                strict::handle_strict(download, upload, preset, diagnose, &target[0], iface_value)
            }
        }

        Some(Commands::Unstrict { target }) => strict::handle_unstrict(&target),

        Some(Commands::Refresh { target }) => strict::handle_refresh(&target),

        Some(Commands::Run {
            dry_run,
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            mkdir_live,
            target,
            scope_mode,
            download,
            upload,
            command,
        }) => run::handle_run(
            dry_run,
            execute,
            probe_live,
            attach_live,
            experimental_single_pid_attach,
            i_understand_this_moves_pids,
            rollback_required,
            mkdir_live,
            target,
            scope_mode,
            download,
            upload,
            &command,
        ),

        Some(Commands::Status) => strict::handle_status(),

        Some(Commands::Clean { all }) => strict::handle_clean(all),

        Some(Commands::Log {
            snapshot,
            last,
            json,
        }) => monitor::handle_log(snapshot, last, json),

        Some(Commands::Profile { command }) => match command {
            ProfileCommands::Save {
                name,
                download,
                upload,
            } => profile::handle_profile_save(&name, download.as_deref(), upload.as_deref()),
            ProfileCommands::Apply { name, target } => {
                profile::handle_profile_apply(&name, &target, iface_value)
            }
            ProfileCommands::List => profile::handle_profile_list(),
            ProfileCommands::Delete { name } => profile::handle_profile_delete(&name),
        },

        Some(Commands::Qos { command }) => match command {
            QosCommands::High { target } => profile::handle_qos_high(&target, iface_value),
            QosCommands::Low { target } => profile::handle_qos_low(&target, iface_value),
            QosCommands::Status => profile::handle_qos_status(),
            QosCommands::Reset => profile::handle_qos_reset(iface_value),
        },

        Some(Commands::Watch {
            alert,
            target,
            interval,
            notify_cmd,
        }) => monitor::handle_watch(&target, &alert, interval, notify_cmd.as_deref()),

        Some(Commands::Auto {
            download,
            upload,
            target,
            kill,
            daemon,
            interval,
            status,
        }) => monitor::handle_auto(
            download.as_deref(),
            upload.as_deref(),
            target.as_deref(),
            kill,
            daemon,
            interval,
            iface_value,
            status,
        ),

        Some(Commands::Completions { shell }) => backend::handle_completions(&shell),

        Some(Commands::Man) => backend::generate_man_page(),

        Some(Commands::Backend { command }) => match command {
            Some(BackendCommands::Doctor(args)) => backend::handle_doctor(args.json),
            None => backend::handle_backend_info(),
        },

        // eBPF observer + limiter engine (experimental)
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
            }) => {
                #[cfg(feature = "ebpf")]
                {
                    handle_ebpf_enforce(limits, stats_interval, duration)
                }
                #[cfg(not(feature = "ebpf"))]
                {
                    let _ = (limits, stats_interval, duration);
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

        // Experimental pre-launch cgroup wrapper (hidden lab command).
        Some(Commands::StrictRunLab {
            download,
            upload,
            diagnose,
            command,
        }) => {
            strict_run_lab::handle_strict_run_lab(download, upload, diagnose, iface_value, &command)
        }

        // v3.1 phase 10: ledger inspect wired to fixture preview; export remains blocked.
        Some(Commands::Ledger { command }) => match command {
            LedgerCommands::Inspect { json, file } => {
                ledger::handle_ledger_inspect(json, file.as_deref())
            }
            LedgerCommands::Export { json, file } => {
                ledger::handle_ledger_export(json, file.as_deref())
            }
        },

        // v3.0 usage: handle existing flags, reject future-gated flags.
        Some(Commands::Usage {
            sample: true,
            json,
            delta,
            session,
            since_boot,
            usage_interface,
            usage_target,
        }) => {
            // Reject any future-gated flags that were parsed.
            if session {
                return Err(anyhow::anyhow!(
                    "{}",
                    render_design_gated_message("usage --session")
                ));
            }
            if since_boot {
                return Err(anyhow::anyhow!(
                    "{}",
                    render_design_gated_message("usage --since-boot")
                ));
            }
            if usage_interface.is_some() {
                return Err(anyhow::anyhow!(
                    "{}",
                    render_design_gated_message("usage --interface")
                ));
            }
            if usage_target.is_some() {
                return Err(anyhow::anyhow!(
                    "{}",
                    render_design_gated_message("usage --target")
                ));
            }
            // No future-gated flags: proceed with existing v3.0 behavior.
            usage::handle_usage_sample(json, delta)
        }

        Some(Commands::Usage { sample: false, .. }) => usage::handle_usage_no_sample(),

        None => {
            // No subcommand: print help
            Cli::parse_from(["zelynic", "--help"]);
            Ok(())
        }
    }
}

/// eBPF observer: load BPF program, attach, read counters, print summary.
///
/// Wolf Architecture flow:
///   Layer 0 (kernel): BPF cgroup_skb/egress program updates cgroup_counters map
///   Layer 1 (map):    read_counters() drains the map
///   Layer 2 (userspace): IdentityMap resolves cgroup IDs to process names
///   Layer 3 (userspace): poll_and_summarize() aggregates + computes deltas
///   Layer 4 (presentation): CounterSummary::print() with identity labels
#[cfg(feature = "ebpf")]
fn handle_ebpf_observe(duration: u64, interval: u64) -> Result<()> {
    use crate::ebpf::loader::Observer;
    use std::time::{Duration, Instant};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("eBPF observer requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required for eBPF observer"));
    }

    let mut observer = Observer::attach()?;

    // Prime the identity map before the first poll so the very first summary
    // already has human-readable labels instead of raw `cg:{id}`.
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

    // Final summary
    let summary = observer.poll_and_summarize()?;
    summary.print(observer.identity());
    observer.detach();
    Ok(())
}

/// eBPF limiter: load BPF program, apply policies, enforce rates, print stats.
///
/// Wolf Architecture flow:
///   Layer 0 (kernel): BPF cgroup_skb/egress program enforces token-bucket
///   Layer 1 (map):    policy writes → cgroup_policy, stats reads ← cgroup_limiter_stats
///   Layer 2 (userspace): IdentityMap resolves process names to cgroup IDs
///   Layer 4 (presentation): print_stats() with identity labels
///
/// Fail-safe: BPF program returns 1 (allow) on any error path.
#[cfg(feature = "ebpf")]
fn handle_ebpf_enforce(limits: Vec<String>, stats_interval: u64, duration: u64) -> Result<()> {
    use crate::ebpf::limiter::{default_burst, parse_policy_spec, Limiter, PolicySpec};
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

    // Parse all policy specs upfront — fail fast on bad input.
    let mut specs: Vec<PolicySpec> = Vec::new();
    for (i, limit_str) in limits.iter().enumerate() {
        let (target, rate_bps) = parse_policy_spec(limit_str)?;
        let burst_bytes = default_burst(rate_bps);
        eprintln!(
            "[limiter] Parsed policy #{}: {} → {}/s (burst: {})",
            i + 1,
            target,
            format_burst(rate_bps),
            format_burst(burst_bytes)
        );
        specs.push(PolicySpec {
            target,
            rate_bps,
            burst_bytes,
        });
    }

    // Attach BPF limiter.
    let mut limiter = Limiter::attach()?;

    // Apply all policies.
    let applied = limiter.apply_policies(&specs)?;
    eprintln!(
        "[limiter] {} polic{} applied. Enforcing.\n",
        applied,
        if applied == 1 { "y" } else { "ies" }
    );

    if applied == 0 {
        eprintln!("[limiter] No policies could be applied. Exiting.");
        limiter.detach();
        return Ok(());
    }

    let start = Instant::now();
    let stats_dur = if stats_interval > 0 {
        Duration::from_secs(stats_interval)
    } else {
        Duration::from_secs(u64::MAX / 2) // effectively never
    };
    let mut last_print = Instant::now();

    loop {
        if last_print.elapsed() >= stats_dur {
            limiter.print_stats();
            last_print = Instant::now();
        }

        if duration > 0 && start.elapsed() >= Duration::from_secs(duration) {
            eprintln!("\n[limiter] Duration reached, stopping...");
            break;
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    // Final stats.
    limiter.print_stats();
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
