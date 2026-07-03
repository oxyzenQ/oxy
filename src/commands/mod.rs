// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for zelynic CLI (Wolf Architecture — pure eBPF).

pub(crate) mod backend;
pub(crate) mod help;

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::cli::{Cli, Commands};

/// Pin directory for BPF maps (shared between parent and child).
#[cfg(feature = "ebpf")]
const PIN_DIR: &str = "/sys/fs/bpf/zelynic";
#[cfg(feature = "ebpf")]
const PIN_MAP_POLICY_DL: &str = "/sys/fs/bpf/zelynic/cgroup_policy_dl";
#[cfg(feature = "ebpf")]
const PIN_MAP_POLICY_UL: &str = "/sys/fs/bpf/zelynic/cgroup_policy_ul";
#[cfg(feature = "ebpf")]
const PIN_MAP_WATCHDOG: &str = "/sys/fs/bpf/zelynic/watchdog_deadline";
#[cfg(feature = "ebpf")]
const PIN_MAP_STATS: &str = "/sys/fs/bpf/zelynic/cgroup_limiter_stats";
#[cfg(feature = "ebpf")]
const PID_FILE: &str = "/tmp/zelynic.pid";

/// Top-level CLI dispatch.
pub(crate) fn dispatch(cli: Cli) -> Result<()> {
    // Serve mode: this is the background child process.
    // It loads BPF, pins maps, and keeps BPF alive until killed.
    #[cfg(feature = "ebpf")]
    if cli.serve {
        return handle_serve(&cli);
    }

    match cli.command {
        Some(Commands::StrictSingle {
            target,
            rate,
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
                    rate.as_deref(),
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
                    rate,
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
            rate,
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
                    rate.as_deref(),
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
                    rate,
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

/// Check if serve child is running.
#[cfg(feature = "ebpf")]
fn child_alive() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            // kill -0 checks if process exists without sending signal.
            return nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok();
        }
    }
    false
}

/// Spawn the serve child process. It loads BPF, pins maps, and keeps BPF alive.
#[cfg(feature = "ebpf")]
fn spawn_serve_child(verbose: bool) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let exe = std::env::current_exe().context("Failed to get current exe")?;
    let mut cmd = Command::new(&exe);
    cmd.arg("--serve");

    // Pass through the same command + args.
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--serve")
        .collect();
    for arg in &args {
        cmd.arg(arg);
    }

    // Redirect child stdout/stderr to /dev/null (it's a background process).
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.stdin(std::process::Stdio::null());

    // Critical: call setsid() in the child before exec.
    // This creates a new session + process group, so the child is NOT
    // killed when the parent exits (no SIGHUP). Without this, the child
    // dies when the parent zelynic process exits.
    unsafe {
        cmd.pre_exec(|| {
            // Create new session — detach from parent's process group.
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn().context("Failed to spawn serve child")?;
    let pid = child.id();

    // Write PID file.
    std::fs::write(PID_FILE, pid.to_string()).context("Failed to write PID file")?;

    if verbose {
        eprintln!("[limiter] Serve child spawned (PID {pid})");
    }

    // Wait for maps to be pinned (child needs time to load BPF + pin).
    for _ in 0..50 {
        // 50 × 100ms = 5s timeout
        if std::path::Path::new(PIN_MAP_POLICY_DL).exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    bail!("Serve child failed to pin maps within 5 seconds. Check 'zelynic -v strict-single ...' for errors.")
}

/// Serve mode handler — runs as background child process.
/// Loads BPF, pins maps, applies initial policies, refreshes watchdog until killed.
#[cfg(feature = "ebpf")]
fn handle_serve(cli: &Cli) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};
    use std::time::{Duration, Instant};

    // Parse the strict command from cli.
    match &cli.command {
        Some(Commands::StrictSingle {
            target,
            rate,
            download,
            upload,
            watchdog,
            allow_dangerous,
            ..
        }) => {
            let rates = resolve_rates(
                rate.as_deref(),
                download.as_deref(),
                upload.as_deref(),
                *allow_dangerous,
            )?;

            let target_obj = Target::parse(target);
            let watchdog = if *watchdog < 5 { 5 } else { *watchdog };

            // Load BPF, attach, pin maps.
            std::fs::create_dir_all(PIN_DIR)?;
            let mut limiter = Limiter::attach(cli.verbose)?;
            limiter.refresh_watchdog(watchdog)?;

            // Pin maps so parent can access them.
            pin_maps(&limiter)?;

            // Apply initial policies.
            limiter.apply_single(&target_obj, &rates)?;

            // Loop: refresh watchdog until killed.
            let _start = Instant::now();
            loop {
                if let Err(e) = limiter.refresh_watchdog(watchdog) {
                    eprintln!("[serve] watchdog refresh failed: {e}");
                }
                std::thread::sleep(Duration::from_millis(200));

                // Check if we should exit (duration-based, for testing).
                // Default duration=5 means run for 5 seconds then exit.
                // duration=0 means run forever.
                // Actually in serve mode, we run forever until SIGTERM.
                // But we keep duration for backwards compat with --duration 0.
            }
        }
        Some(Commands::StrictMulti {
            targets,
            rate,
            download,
            upload,
            watchdog,
            allow_dangerous,
            ..
        }) => {
            let rates = resolve_rates(
                rate.as_deref(),
                download.as_deref(),
                upload.as_deref(),
                *allow_dangerous,
            )?;

            let target_list: Vec<Target> = targets
                .split(':')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(Target::parse)
                .collect();

            let watchdog = if *watchdog < 5 { 5 } else { *watchdog };

            std::fs::create_dir_all(PIN_DIR)?;
            let mut limiter = Limiter::attach(cli.verbose)?;
            limiter.refresh_watchdog(watchdog)?;
            pin_maps(&limiter)?;
            limiter.apply_group(&target_list, &rates)?;

            loop {
                if let Err(e) = limiter.refresh_watchdog(watchdog) {
                    eprintln!("[serve] watchdog refresh failed: {e}");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        _ => {
            bail!("--serve mode only works with strict-single or strict-multi");
        }
    }
}

/// Pin BPF maps to /sys/fs/bpf/zelynic/ for parent access.
#[cfg(feature = "ebpf")]
fn pin_maps(limiter: &crate::ebpf::limiter::Limiter) -> Result<()> {
    limiter.pin_map("cgroup_policy_dl", PIN_MAP_POLICY_DL)?;
    limiter.pin_map("cgroup_policy_ul", PIN_MAP_POLICY_UL)?;
    limiter.pin_map("watchdog_deadline", PIN_MAP_WATCHDOG)?;
    limiter.pin_map("cgroup_limiter_stats", PIN_MAP_STATS)?;
    Ok(())
}

/// Kill serve child and cleanup.
#[cfg(feature = "ebpf")]
fn kill_serve_child() -> Result<()> {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                Some(nix::sys::signal::Signal::SIGTERM),
            );
            // Wait for child to exit (max 3 seconds).
            for _ in 0..30 {
                if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
                    break; // process gone
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // Force kill if still alive.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                Some(nix::sys::signal::Signal::SIGKILL),
            );
        }
    }

    // Remove PID file + pin files.
    let _ = std::fs::remove_file(PID_FILE);
    let _ = std::fs::remove_file(PIN_MAP_POLICY_DL);
    let _ = std::fs::remove_file(PIN_MAP_POLICY_UL);
    let _ = std::fs::remove_file(PIN_MAP_WATCHDOG);
    let _ = std::fs::remove_file(PIN_MAP_STATS);
    let _ = std::fs::remove_dir(PIN_DIR);
    Ok(())
}

#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
fn handle_strict_single(
    target_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    _watchdog: u64,
    allow_dangerous: bool,
    _duration: u64,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-single brave 100kb"
        ));
    }

    let target = Target::parse(target_str);

    // If no serve child running, spawn one.
    if !child_alive() {
        spawn_serve_child(verbose)?;
    }

    // Open pinned maps and write policy directly.
    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_single(&target, &rates)?;
    if applied == 0 {
        eprintln!("No cgroup found for '{target_str}'. Nothing to limit.");
        return Ok(());
    }

    // Print summary and exit 0 — limit persists in background.
    print_pin_summary(target_str, &rates, applied);
    Ok(())
}

#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
fn handle_strict_multi(
    targets_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    _watchdog: u64,
    allow_dangerous: bool,
    _duration: u64,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-multi brave:curl 1mb"
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
             Example: zelynic strict-multi brave:curl:pacman 1mb"
        ));
    }

    // If no serve child running, spawn one.
    if !child_alive() {
        spawn_serve_child(verbose)?;
    }

    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_group(&targets, &rates)?;
    if applied == 0 {
        eprintln!("No cgroups found for any target in '{targets_str}'. Nothing to limit.");
        return Ok(());
    }

    print_pin_summary(targets_str, &rates, applied);
    Ok(())
}

/// Print summary for pin mode (fire-and-forget).
#[cfg(feature = "ebpf")]
fn print_pin_summary(target_str: &str, rates: &crate::ebpf::limiter::RateSpec, applied: usize) {
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
        "Limiting '{target_str}' to {} ({applied} policies, active in background)",
        parts.join(" + ")
    );
    eprintln!("Run 'zelynic unstrict {target_str}' to remove, 'zelynic status' to check.");
}

/// Print the one-liner summary line for strict commands.
#[cfg(feature = "ebpf")]
#[allow(dead_code)]
fn print_summary_line(
    target_str: &str,
    rates: &crate::ebpf::limiter::RateSpec,
    applied: usize,
    duration: u64,
) {
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

    let exit_info = if duration > 0 {
        format!("{duration} seconds will be self-exit")
    } else {
        "Ctrl+C to stop".to_string()
    };

    eprintln!(
        "Limiting '{target_str}' to {} ({applied} policies, {exit_info})",
        parts.join(" + ")
    );
}

/// Parse a rate string with validation.
#[cfg(feature = "ebpf")]
fn parse_rate_checked(s: &str, allow_dangerous: bool) -> Result<u64> {
    use crate::ebpf::limiter::{parse_rate, validate_rate, MIN_RATE};
    let rate = parse_rate(s)?;
    if !allow_dangerous {
        validate_rate(rate)?;
    } else if rate < MIN_RATE {
        eprintln!("[limiter] WARNING: rate below minimum — overriding with --allow-dangerous");
    }
    Ok(rate)
}

/// Resolve rates from CLI args. Priority: -d/-u flags > positional rate.
///
/// If -d or -u is specified, use those (per-direction).
/// If neither -d nor -u, but positional rate exists, use it for BOTH directions.
/// If nothing specified, return empty RateSpec (caller should error).
#[cfg(feature = "ebpf")]
fn resolve_rates(
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    allow_dangerous: bool,
) -> Result<crate::ebpf::limiter::RateSpec> {
    if download.is_some() || upload.is_some() {
        // -d or -u specified → use per-direction.
        parse_rates(download, upload, allow_dangerous)
    } else if let Some(r) = rate {
        // No -d/-u, but positional rate → both = rate.
        let r_bps = parse_rate_checked(r, allow_dangerous)?;
        Ok(crate::ebpf::limiter::RateSpec {
            download: Some(r_bps),
            upload: Some(r_bps),
        })
    } else {
        // Nothing specified.
        Ok(crate::ebpf::limiter::RateSpec {
            download: None,
            upload: None,
        })
    }
}

#[cfg(feature = "ebpf")]
fn handle_unstrict(target_str: &str, verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    if !child_alive() {
        eprintln!("No active limits. Nothing to remove.");
        return Ok(());
    }

    let target = Target::parse(target_str);
    let mut limiter = Limiter::open_pinned(verbose)?;
    let removed = limiter.unstrict(&target)?;

    if removed == 0 {
        eprintln!("No active limits found for '{target_str}'");
    } else {
        eprintln!(
            "Removed {removed} limit{} for '{target_str}'",
            if removed == 1 { "" } else { "s" }
        );
    }

    // If no policies remain, kill serve child (no residue).
    let dl = limiter
        .read_policies_public(crate::ebpf::limiter::Direction::Download)
        .unwrap_or_default();
    let ul = limiter
        .read_policies_public(crate::ebpf::limiter::Direction::Upload)
        .unwrap_or_default();
    if dl.is_empty() && ul.is_empty() {
        kill_serve_child()?;
        if verbose {
            eprintln!("[limiter] No policies remain — serve child killed, no residue");
        }
    }

    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_unstrict_all(_verbose: bool) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    if !child_alive() {
        eprintln!("No active limits. Nothing to remove.");
        return Ok(());
    }

    kill_serve_child()?;
    eprintln!("All limits removed, serve child killed, no residue.");
    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_status(verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::Limiter;

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    if !child_alive() {
        eprintln!("No active limits.");
        return Ok(());
    }

    let mut limiter = Limiter::open_pinned(verbose)?;
    limiter.refresh_identity();
    limiter.print_status();
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
#[allow(dead_code)]
fn run_enforcement_loop(
    limiter: &mut crate::ebpf::limiter::Limiter,
    watchdog: u64,
    duration: u64,
    verbose: bool,
) {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let stats_interval = Duration::from_secs(1);
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
#[allow(dead_code)]
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
