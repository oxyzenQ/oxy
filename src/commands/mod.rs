// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command handlers for zelynic CLI (Dragon Architecture — pure eBPF).

pub(crate) mod backend;
pub(crate) mod help;

#[cfg(not(feature = "ebpf"))]
use anyhow::Result;
#[cfg(feature = "ebpf")]
use anyhow::Result;
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
const PIN_MAP_BUCKET_DL: &str = "/sys/fs/bpf/zelynic/cgroup_bucket_dl";
#[cfg(feature = "ebpf")]
const PIN_MAP_BUCKET_UL: &str = "/sys/fs/bpf/zelynic/cgroup_bucket_ul";
#[cfg(feature = "ebpf")]
const PIN_MAP_GROUP_BUCKET_DL: &str = "/sys/fs/bpf/zelynic/group_bucket_dl";
#[cfg(feature = "ebpf")]
const PIN_MAP_GROUP_BUCKET_UL: &str = "/sys/fs/bpf/zelynic/group_bucket_ul";
#[cfg(feature = "ebpf")]
const PIN_MAP_WATCHDOG: &str = "/sys/fs/bpf/zelynic/watchdog_deadline";
#[cfg(feature = "ebpf")]
const PIN_MAP_STATS: &str = "/sys/fs/bpf/zelynic/cgroup_limiter_stats";
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
            watchdog,
            allow_dangerous,
            force,
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
                    force,
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
                    force,
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
            force,
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
                    force,
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
                    force,
                    duration,
                    cli.verbose,
                );
                eprintln!("eBPF not compiled. Rebuild with: cargo build --features ebpf");
                Err(anyhow::anyhow!("eBPF feature not enabled"))
            }
        }

        Some(Commands::AllLimit {
            rate,
            download,
            upload,
            watchdog,
            allow_dangerous,
            force,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_all_limit(
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    watchdog,
                    allow_dangerous,
                    force,
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (
                    rate,
                    download,
                    upload,
                    watchdog,
                    allow_dangerous,
                    force,
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
/// Remove ALL BPF pin files (programs + maps). Full cleanup.
#[cfg(feature = "ebpf")]
fn unpin_all_bpf() -> Result<()> {
    // Remove program pins.
    let _ = std::fs::remove_file("/sys/fs/bpf/zelynic/enforce_dl");
    let _ = std::fs::remove_file("/sys/fs/bpf/zelynic/enforce_ul");
    // Remove map pins — all 8 maps are now pinned via LIBBPF_PIN_BY_NAME.
    let _ = std::fs::remove_file(PIN_MAP_POLICY_DL);
    let _ = std::fs::remove_file(PIN_MAP_POLICY_UL);
    let _ = std::fs::remove_file(PIN_MAP_WATCHDOG);
    let _ = std::fs::remove_file(PIN_MAP_STATS);
    let _ = std::fs::remove_file(PIN_MAP_BUCKET_DL);
    let _ = std::fs::remove_file(PIN_MAP_BUCKET_UL);
    let _ = std::fs::remove_file(PIN_MAP_GROUP_BUCKET_DL);
    let _ = std::fs::remove_file(PIN_MAP_GROUP_BUCKET_UL);
    // Remove PID file (legacy).
    let _ = std::fs::remove_file(PID_FILE);
    // Remove pin directory. Use remove_dir_all as a safety net in case any
    // pin file was missed above (e.g. from a future map addition).
    let _ = std::fs::remove_dir_all(PIN_DIR);
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
fn check_dangerous_target(target_str: &str, force: bool) -> Result<()> {
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
    _watchdog: u64,
    allow_dangerous: bool,
    force: bool,
    _duration: u64,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

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
    _watchdog: u64,
    allow_dangerous: bool,
    force: bool,
    _duration: u64,
    verbose: bool,
) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

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

/// Handle `zelynic all-limit` — limit ALL user apps.
/// System/dangerous apps are excluded unless --force.
#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
fn handle_all_limit(
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    _watchdog: u64,
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

    let rates = resolve_rates(rate, download, upload, allow_dangerous)?;

    if rates.download.is_none() && rates.upload.is_none() {
        return Err(anyhow::anyhow!(
            "No rate specified. Use positional rate or -d/-u flags.\n\
             Example: zelynic all-limit 500kb"
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
            .map(|r| format!("{} /s", crate::ebpf::limiter::format_rate(r)))
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

    if !crate::ebpf::limiter::Limiter::is_pinned() {
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
        unpin_all_bpf()?;
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

    if !crate::ebpf::limiter::Limiter::is_pinned() {
        eprintln!("No active limits. Nothing to remove.");
        return Ok(());
    }

    unpin_all_bpf()?;
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

    if !crate::ebpf::limiter::Limiter::is_pinned() {
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
