// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for zelynic CLI (Wolf Architecture — pure eBPF).

pub(crate) mod backend;
pub(crate) mod help;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Commands};

/// Top-level CLI dispatch.
pub(crate) fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::StrictSingle {
            target,
            download,
            upload,
            watchdog,
            allow_dangerous,
            duration,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_strict_single(
                    &target,
                    download.as_deref(),
                    upload.as_deref(),
                    watchdog,
                    allow_dangerous,
                    duration,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (
                    target,
                    download,
                    upload,
                    watchdog,
                    allow_dangerous,
                    duration,
                    cli.verbose,
                );
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::StrictMulti {
            targets,
            download,
            upload,
            watchdog,
            allow_dangerous,
            duration,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_strict_multi(
                    &targets,
                    download.as_deref(),
                    upload.as_deref(),
                    watchdog,
                    allow_dangerous,
                    duration,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (
                    targets,
                    download,
                    upload,
                    watchdog,
                    allow_dangerous,
                    duration,
                    cli.verbose,
                );
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Unstrict { target }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_unstrict(&target, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::UnstrictAll) => {
            #[cfg(feature = "ebpf")]
            {
                handle_unstrict_all(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Status) => {
            #[cfg(feature = "ebpf")]
            {
                handle_status(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::ListApps) => {
            #[cfg(feature = "ebpf")]
            {
                handle_list_apps()
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Observe { interval, duration }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_observe(interval, duration, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (interval, duration, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Doctor) => crate::capabilities::run_doctor(false),

        Some(Commands::Completions { shell }) => backend::handle_completions(&shell),

        Some(Commands::Man) => backend::generate_man_page(),

        None => {
            if cli.help_all {
                help::print_help_all();
                Ok(())
            } else {
                Cli::parse_from(["zelynic", "--help"]);
                Ok(())
            }
        }
    }
}

// ━━ Command handlers (ebpf feature) ━━

#[cfg(feature = "ebpf")]
fn handle_strict_single(
    target_str: &str,
    download: Option<&str>,
    upload: Option<&str>,
    watchdog: u64,
    allow_dangerous: bool,
    duration: u64,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let rates = parse_rates(download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use -d <rate> for download, -u <rate> for upload.\n\
             Example: zelynic strict-single brave -d 100KB/s"
        ));
    }

    let target = Target::parse(target_str);
    let watchdog = if watchdog < 5 { 5 } else { watchdog };

    let mut limiter = Limiter::attach(verbose)?;
    limiter.refresh_watchdog(watchdog)?;

    let applied = limiter.apply_single(&target, &rates)?;
    if applied == 0 {
        eprintln!("No cgroup found for '{target_str}'. Nothing to limit.");
        limiter.detach();
        return Ok(());
    }

    // Clean one-liner summary (quiet by default).
    let dl_str = rates
        .download
        .map(|r| format!("{} /s", crate::ebpf::limiter::format_rate(r)))
        .unwrap_or_default();
    let ul_str = rates
        .upload
        .map(|r| format!("{} /s", crate::ebpf::limiter::format_rate(r)))
        .unwrap_or_default();
    let parts: Vec<&str> = [
        if !dl_str.is_empty() {
            dl_str.as_str()
        } else {
            ""
        },
        if !ul_str.is_empty() {
            ul_str.as_str()
        } else {
            ""
        },
    ]
    .iter()
    .filter(|s| !s.is_empty())
    .copied()
    .collect();
    eprintln!(
        "Limiting '{target_str}' to {} ({} polic{}, Ctrl+C to stop)",
        parts.join(" + "),
        applied,
        if applied == 1 { "y" } else { "ies" }
    );

    run_enforcement_loop(&mut limiter, watchdog, duration, verbose);
    limiter.detach();
    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_strict_multi(
    targets_str: &str,
    download: Option<&str>,
    upload: Option<&str>,
    watchdog: u64,
    allow_dangerous: bool,
    duration: u64,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let rates = parse_rates(download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use -d <rate> for download, -up <rate> for upload.\n\
             Example: zelynic strict-multi brave:curl -d 1MB/s"
        ));
    }

    let targets: Vec<Target> = targets_str
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(Target::parse)
        .collect();

    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "No targets specified. Use colon-separated list.\n\
             Example: zelynic strict-multi brave:curl:pacman -d 1MB/s"
        ));
    }

    let watchdog = if watchdog < 5 { 5 } else { watchdog };

    let mut limiter = Limiter::attach(verbose)?;
    limiter.refresh_watchdog(watchdog)?;

    let applied = limiter.apply_group(&targets, &rates)?;
    if applied == 0 {
        eprintln!("No cgroups found for any target in '{targets_str}'. Nothing to limit.");
        limiter.detach();
        return Ok(());
    }

    // Clean one-liner summary (quiet by default).
    let dl_str = rates
        .download
        .map(|r| format!("{} /s", crate::ebpf::limiter::format_rate(r)))
        .unwrap_or_default();
    let ul_str = rates
        .upload
        .map(|r| format!("{} /s", crate::ebpf::limiter::format_rate(r)))
        .unwrap_or_default();
    let parts: Vec<&str> = [
        if !dl_str.is_empty() {
            dl_str.as_str()
        } else {
            ""
        },
        if !ul_str.is_empty() {
            ul_str.as_str()
        } else {
            ""
        },
    ]
    .iter()
    .filter(|s| !s.is_empty())
    .copied()
    .collect();
    eprintln!(
        "Limiting group '{targets_str}' to {} ({applied} policies, Ctrl+C to stop)",
        parts.join(" + ")
    );

    run_enforcement_loop(&mut limiter, watchdog, duration, verbose);
    limiter.detach();
    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_unstrict(target_str: &str, verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let target = Target::parse(target_str);

    // Attach temporarily (we need BPF loaded to access maps).
    let mut limiter = Limiter::attach(verbose)?;
    let removed = limiter.unstrict(&target)?;

    if removed == 0 {
        eprintln!("[limiter] No active limits found for '{target_str}'");
    } else {
        eprintln!(
            "[limiter] Removed {removed} limit{} for '{target_str}'",
            if removed == 1 { "" } else { "s" }
        );
    }

    limiter.detach();
    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_unstrict_all(verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::Limiter;

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let mut limiter = Limiter::attach(verbose)?;
    limiter.unstrict_all()?;
    limiter.detach();
    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_status(verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::Limiter;

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let mut limiter = Limiter::attach(verbose)?;
    limiter.refresh_identity();
    limiter.print_status();
    limiter.detach();
    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_list_apps() -> Result<()> {
    use crate::ebpf::identity::IdentityMap;
    use colored::Colorize;

    let mut identity = IdentityMap::new();
    let count = identity.refresh();

    println!("{}", "━━━ Apps with cgroup IDs ━━━".bold());
    println!("  {} cgroups resolved\n", count);

    let mut entries: Vec<_> = identity.all().into_iter().collect();
    entries.sort_by(|a, b| a.comm.cmp(&b.comm));

    println!("  {:<30} {:>10} {:>8}", "PROCESS", "CGROUP ID", "UID");
    println!("  {}", "─".repeat(50));

    for id in entries {
        if id.comm.is_empty() {
            continue;
        }
        println!(
            "  {:<30} {:>10} {:>8}",
            id.comm,
            format!("cg:{}", id.cgroup_id),
            id.uid
        );
    }

    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_observe(interval: u64, duration: u64, verbose: bool) -> Result<()> {
    use crate::ebpf::loader::Observer;
    use std::time::{Duration, Instant};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let mut observer = Observer::attach()?;
    let resolved = observer.refresh_identity();
    if verbose {
        eprintln!("[ebpf] {} cgroups resolved", resolved);
    }
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
            break;
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    let summary = observer.poll_and_summarize()?;
    summary.print(observer.identity());
    observer.detach();
    Ok(())
}

// ━━ Helpers ━━

#[cfg(feature = "ebpf")]
fn parse_rates(
    download: Option<&str>,
    upload: Option<&str>,
    allow_dangerous: bool,
) -> Result<crate::ebpf::limiter::RateSpec> {
    use crate::ebpf::limiter::{parse_rate, validate_rate, MIN_RATE};

    let dl = match download {
        Some(s) => {
            let rate = parse_rate(s)?;
            if !allow_dangerous {
                validate_rate(rate)?;
            } else if rate < MIN_RATE {
                eprintln!(
                    "[limiter] WARNING: rate below minimum — overriding with --allow-dangerous"
                );
            }
            Some(rate)
        }
        None => None,
    };

    let ul = match upload {
        Some(s) => {
            let rate = parse_rate(s)?;
            if !allow_dangerous {
                validate_rate(rate)?;
            } else if rate < MIN_RATE {
                eprintln!(
                    "[limiter] WARNING: rate below minimum — overriding with --allow-dangerous"
                );
            }
            Some(rate)
        }
        None => None,
    };

    Ok(crate::ebpf::limiter::RateSpec {
        download: dl,
        upload: ul,
    })
}

#[cfg(feature = "ebpf")]
fn run_enforcement_loop(
    limiter: &mut crate::ebpf::limiter::Limiter,
    watchdog: u64,
    duration: u64,
    verbose: bool,
) {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let stats_interval = Duration::from_secs(5);
    let mut last_print = Instant::now();

    loop {
        if let Err(e) = limiter.refresh_watchdog(watchdog) {
            if verbose {
                eprintln!("[limiter] WARNING: watchdog refresh failed: {e}");
            }
        }

        if last_print.elapsed() >= stats_interval {
            if verbose {
                // Verbose: full status table.
                limiter.print_status();
            } else {
                // Quiet: one-line summary.
                print_compact_status(limiter);
            }
            last_print = Instant::now();
        }

        if duration > 0 && start.elapsed() >= Duration::from_secs(duration) {
            break;
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Print a compact one-line status (quiet mode).
#[cfg(feature = "ebpf")]
fn print_compact_status(limiter: &crate::ebpf::limiter::Limiter) {
    use crate::ebpf::limiter::Direction;
    use std::collections::HashMap;

    let dl_policies = limiter
        .read_policies_public(Direction::Download)
        .unwrap_or_default();
    let ul_policies = limiter
        .read_policies_public(Direction::Upload)
        .unwrap_or_default();
    let stats = limiter.read_stats_public().unwrap_or_default();

    if dl_policies.is_empty() && ul_policies.is_empty() {
        return;
    }

    let mut combined: HashMap<u32, (Option<u64>, Option<u64>)> = HashMap::new();
    for (id, p) in &dl_policies {
        combined.entry(*id).or_default().0 = Some(p.rate_bps);
    }
    for (id, p) in &ul_policies {
        combined.entry(*id).or_default().1 = Some(p.rate_bps);
    }

    let total_allowed: u64 = stats.iter().map(|(_, s)| s.bytes_allowed).sum();
    let total_dropped: u64 = stats.iter().map(|(_, s)| s.bytes_dropped).sum();
    let active = combined.len();

    eprintln!(
        "  [{active} limits] allowed: {} | dropped: {}",
        crate::ebpf::limiter::format_bytes(total_allowed),
        crate::ebpf::limiter::format_bytes(total_dropped),
    );
}
