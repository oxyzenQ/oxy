// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for zelynic CLI (Dragon Architecture — pure eBPF).

pub(crate) mod backend;
#[cfg(feature = "ebpf")]
pub(crate) mod block;
#[cfg(feature = "ebpf")]
pub(crate) mod cleanup;
pub(crate) mod help;
#[cfg(feature = "ebpf")]
pub(crate) mod monitor;

#[cfg(not(feature = "ebpf"))]
use anyhow::Result;
#[cfg(feature = "ebpf")]
use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Commands};

#[cfg(feature = "ebpf")]
use crate::ebpf::pin::unpin_all;

/// Legacy PID file (kept for cleanup of old installations).
#[cfg(feature = "ebpf")]
const PID_FILE: &str = "/tmp/zelynic.pid";

/// Top-level CLI dispatch.
pub(crate) fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::StrictSingle {
            target,
            rate,
            download,
            upload,
            allow_dangerous,
            force,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_strict_single(
                    &target,
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    allow_dangerous,
                    force,
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
                    allow_dangerous,
                    force,
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
            allow_dangerous,
            force,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_strict_multi(
                    &targets,
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    allow_dangerous,
                    force,
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
                    allow_dangerous,
                    force,
                    cli.verbose,
                );
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::LimitAll {
            rate,
            download,
            upload,
            allow_dangerous,
            force,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_limit_all(
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    allow_dangerous,
                    force,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (rate, download, upload, allow_dangerous, force, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::BlockSingle { target, force }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_single(&target, force, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, force, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::BlockMulti { targets, force }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_multi(&targets, force, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, force, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::BlockAll { force }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_all(force, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (force, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Unblock { target }) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict(&target, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Unstrict { target }) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict(&target, cli.verbose)
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
                cleanup::handle_unstrict_all(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Recover) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_recover(cli.verbose)
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
                monitor::handle_status(cli.verbose, cli.print_json)
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
                monitor::handle_list_apps(cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Observe { live, cgroup }) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_observe(live.as_deref(), cgroup, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (live, cgroup, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Top {
            duration,
            limit,
            live,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_top(duration.as_deref(), limit, live.as_deref(), cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (duration, limit, live, cli.verbose);
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::Doctor) => crate::capabilities::run_doctor(cli.print_json),

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

/// Remove ALL BPF pin files + directory. Full cleanup.
/// Delegates to `limiter::unpin_all()` which iterates the pin directory
/// and removes every file, then removes the directory. Also removes the
/// legacy PID file if present.
#[cfg(feature = "ebpf")]
pub(crate) fn unpin_all_bpf() -> Result<()> {
    unpin_all()?;
    // Remove legacy PID file if present (from old serve-child versions).
    let _ = std::fs::remove_file(PID_FILE);
    Ok(())
}

/// List of dangerous/system process names that should not be limited
/// without --force flag. Limiting these can destabilize the system.
#[cfg(feature = "ebpf")]
const DANGEROUS_TARGETS: &[&str] = &[
    "root",
    "init",
    "kthreadd",
    "systemd",
    "systemd-journal",
    "systemd-logind",
    "systemd-udevd",
    "systemd-resolve",
    "systemd-timesyn",
    "systemd-hostnam",
    "systemd-machine",
    "systemd-oomd",
    "dbus-daemon",
    "dbus-broker",
    "polkitd",
    "rtkit-daemon",
    "wpa_supplicant",
    "NetworkManager",
    "gdm",
    "gdm3",
    "sddm",
    "sddm-helper",
    "lightdm",
    "sshd",
    "agetty",
    "login",
    "kerneloops",
    "irqbalance",
    "chronyd",
    "snapd",
    "udisksd",
    "upowerd",
    "accounts-daemon",
    "colord",
    "fwupd",
    "ModemManager",
    "avahi-daemon",
    "cupsd",
    "cups-browsed",
    "rsyslogd",
    "cron",
    "atd",
    "acpid",
    "bluetoothd",
    "bluez",
    "pipewire",
    "pipewire-pulse",
    "wireplumber",
    "pulseaudio",
    "gnome-shell",
    "gnome-session",
    "kwin_wayland",
    "kwin_x11",
    "Xorg",
    "Xwayland",
    "ksmserver",
    "plasmashell",
];

/// Check if a target name is dangerous (system process).
#[cfg(feature = "ebpf")]
fn is_dangerous_target(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    DANGEROUS_TARGETS
        .iter()
        .any(|d| d.to_lowercase() == name_lower)
}

/// Validate target against dangerous list. Returns Ok if safe, Err if dangerous.
#[cfg(feature = "ebpf")]
pub(crate) fn check_dangerous_target(target_str: &str, force: bool) -> Result<()> {
    // Numeric cgroup IDs are always allowed (user knows what they're doing).
    if target_str.parse::<u32>().is_ok() {
        return Ok(());
    }

    if is_dangerous_target(target_str) {
        if force {
            eprintln!("WARNING: '{target_str}' is a system process. Forcing with --force.");
            eprintln!("  This may destabilize your system. Use 'zelynic unstrict {target_str}' to remove.");
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "'{target_str}' is a system process. Limiting it may destabilize your system.\n\
                 If you really want to do this, use: zelynic strict-single {target_str} 100kb --force"
            ))
        }
    } else {
        Ok(())
    }
}

#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
fn handle_strict_single(
    target_str: &str,
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    allow_dangerous: bool,
    force: bool,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    check_dangerous_target(target_str, force)?;

    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic strict-single brave 100kb"
        ));
    }

    let target = Target::parse(target_str);

    // Attach BPF programs (pins to /sys/fs/bpf/zelynic/ — survives exit).
    crate::ebpf::limiter::Limiter::attach(verbose)?;

    // Open pinned maps and write policy.
    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_single(&target, &rates)?;
    if applied == 0 {
        eprintln!("No cgroup found for '{target_str}'. Nothing to limit.");
        return Ok(());
    }

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
    allow_dangerous: bool,
    force: bool,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    // Check each target for dangerous names.
    for t in targets_str.split(':') {
        let t = t.trim();
        if !t.is_empty() {
            check_dangerous_target(t, force)?;
        }
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
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        crate::ebpf::limiter::Limiter::attach(verbose)?;
    }

    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_group(&targets, &rates)?;
    if applied == 0 {
        eprintln!("No cgroups found for any target in '{targets_str}'. Nothing to limit.");
        return Ok(());
    }

    print_pin_summary(targets_str, &rates, applied);

    // Verify serve child is still alive after apply.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        let log = std::fs::read_to_string("/tmp/zelynic-serve.log").unwrap_or_default();
        eprintln!("WARNING: Serve child died after applying policies!");
        eprintln!("Log: {log}");
    }
    Ok(())
}

/// Handle `zelynic limit-all` — limit ALL user apps.
/// System/dangerous apps are excluded unless --force.
#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
fn handle_limit_all(
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    allow_dangerous: bool,
    force: bool,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic limit-all 500kb"
        ));
    }

    // Get all apps from identity map.
    let mut identity = IdentityMap::new();
    identity.refresh();

    let mut user_apps: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for app in identity.all() {
        if app.comm.is_empty() {
            continue;
        }
        if is_dangerous_target(&app.comm) {
            if force {
                user_apps.push(app.comm.clone());
            } else {
                skipped.push(app.comm.clone());
            }
        } else {
            user_apps.push(app.comm.clone());
        }
    }

    if user_apps.is_empty() {
        eprintln!("No apps found to limit.");
        return Ok(());
    }

    // Deduplicate (multiple cgroups may have same comm).
    user_apps.sort();
    user_apps.dedup();

    eprintln!(
        "Limiting {} app(s) to {}",
        user_apps.len(),
        rates
            .download
            .map(crate::ebpf::limiter::format_rate)
            .unwrap_or_default()
    );

    if !skipped.is_empty() {
        eprintln!(
            "Skipped {} system app(s) (use --force to include):",
            skipped.len()
        );
        for s in &skipped {
            eprintln!("  - {s}");
        }
    }

    // Build targets list.
    let targets: Vec<Target> = user_apps
        .iter()
        .map(|n| Target::ProcessName(n.clone()))
        .collect();

    // If no serve child running, spawn one.
    if !crate::ebpf::limiter::Limiter::is_pinned() {
        crate::ebpf::limiter::Limiter::attach(verbose)?;
    }

    let mut limiter = Limiter::open_pinned(verbose)?;
    let applied = limiter.apply_group(&targets, &rates)?;

    print_pin_summary(&format!("{} apps", user_apps.len()), &rates, applied);

    if !crate::ebpf::limiter::Limiter::is_pinned() {
        let log = std::fs::read_to_string("/tmp/zelynic-serve.log").unwrap_or_default();
        eprintln!("WARNING: Serve child died after applying policies!");
        eprintln!("Log: {log}");
    }
    Ok(())
}

/// Print summary for pin mode (fire-and-forget).
#[cfg(feature = "ebpf")]
fn print_pin_summary(target_str: &str, rates: &crate::ebpf::limiter::RateSpec, applied: usize) {
    let dl_str = rates
        .download
        .map(crate::ebpf::limiter::format_rate)
        .unwrap_or_default();
    let ul_str = rates
        .upload
        .map(crate::ebpf::limiter::format_rate)
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
        .map(crate::ebpf::limiter::format_rate)
        .unwrap_or_default();
    let ul_str = rates
        .upload
        .map(crate::ebpf::limiter::format_rate)
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
    use crate::ebpf::limiter::{parse_rate, validate_rate, MAX_RATE, MIN_RATE};
    let rate = parse_rate(s)?;
    if !allow_dangerous {
        validate_rate(rate)?;
    } else if rate < MIN_RATE {
        eprintln!("[limiter] WARNING: rate below minimum — overriding with --allow-dangerous");
    } else if rate > MAX_RATE {
        eprintln!("[limiter] WARNING: rate above maximum — overriding with --allow-dangerous");
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
