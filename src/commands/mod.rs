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

// Re-export pin path helpers from limiter module (single source of truth).
#[cfg(feature = "ebpf")]
use crate::ebpf::limiter::{pin_dir_has_files, unpin_all};
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

        Some(Commands::AllLimit {
            rate,
            download,
            upload,
            allow_dangerous,
            force,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                handle_all_limit(
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

        Some(Commands::Recover) => {
            #[cfg(feature = "ebpf")]
            {
                handle_recover(cli.verbose)
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
                handle_status(cli.verbose, cli.print_json)
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
                handle_list_apps(cli.print_json)
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
                handle_observe(live.as_deref(), cgroup, cli.verbose)
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
                handle_top(duration.as_deref(), limit, live.as_deref(), cli.verbose)
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
fn unpin_all_bpf() -> Result<()> {
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

/// Handle `zelynic all-limit` — limit ALL user apps.
/// System/dangerous apps are excluded unless --force.
#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
fn handle_all_limit(
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

#[cfg(feature = "ebpf")]
fn handle_unstrict(target_str: &str, verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::{Limiter, Target};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;
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

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

    // Check if pin directory has any files. Can't rely on is_pinned() because
    // stale pins from old versions (before link pinning) fail the 4-file check
    // but still need cleanup.
    if !pin_dir_has_files() {
        eprintln!("No active limits. Nothing to remove.");
        return Ok(());
    }

    unpin_all_bpf()?;
    eprintln!("All limits removed, no residue.");
    Ok(())
}

/// Handle `zelynic recover` — crash recovery cleanup.
/// Detects orphaned/stale BPF pin files and removes them.
/// Differs from `unstrict-all` in that it's diagnostic: reports what
/// it found before cleaning. Safe to run anytime.
#[cfg(feature = "ebpf")]
fn handle_recover(verbose: bool) -> Result<()> {
    use crate::ebpf::limiter::{pin_dir_has_files, unpin_all, Limiter};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Prevent concurrent operations (race condition elimination).
    let _lock = crate::ebpf::lock::acquire()?;

    eprintln!("━━━ zelynic Crash Recovery ━━━");

    if !pin_dir_has_files() {
        eprintln!("  State: clean (no pin files found)");
        eprintln!("  Action: nothing to recover");
        return Ok(());
    }

    // Check if state is valid (all 4 critical pins present).
    let is_valid = Limiter::is_pinned();

    if is_valid {
        // BPF is valid — check for orphan policies (cgroup dead, policy remains).
        eprintln!("  State: valid (BPF programs + links pinned)");
        eprintln!("  Checking for orphan policies...");

        let mut limiter = Limiter::open_pinned(verbose)?;
        limiter.refresh_identity();

        let dl_policies = limiter
            .read_policies_public(crate::ebpf::limiter::Direction::Download)
            .unwrap_or_default();
        let ul_policies = limiter
            .read_policies_public(crate::ebpf::limiter::Direction::Upload)
            .unwrap_or_default();

        // Collect all cgroup IDs that have policies.
        use std::collections::HashSet;
        let mut policy_cgroup_ids: HashSet<u32> = HashSet::new();
        for (id, _) in &dl_policies {
            policy_cgroup_ids.insert(*id);
        }
        for (id, _) in &ul_policies {
            policy_cgroup_ids.insert(*id);
        }

        // Check which cgroup IDs are still alive (exist in identity map).
        let alive_ids: HashSet<u32> = limiter
            .identity()
            .all()
            .iter()
            .map(|e| e.cgroup_id)
            .collect();

        let orphan_ids: Vec<u32> = policy_cgroup_ids
            .iter()
            .filter(|id| !alive_ids.contains(id))
            .copied()
            .collect();

        if orphan_ids.is_empty() {
            eprintln!(
                "  Orphans: none (all {} policies have live cgroups)",
                policy_cgroup_ids.len()
            );
            eprintln!("  Action: nothing to recover — use 'unstrict-all' to remove limits");
            return Ok(());
        }

        eprintln!(
            "  Orphans: {} policy cgroup(s) no longer exist:",
            orphan_ids.len()
        );
        for id in &orphan_ids {
            eprintln!("    - cg:{id}");
        }
        eprintln!("  Action: removing orphan policies...");

        // Remove orphan policies from BPF maps.
        for id in &orphan_ids {
            let _ = limiter.delete_policy(*id, crate::ebpf::limiter::Direction::Download);
            let _ = limiter.delete_policy(*id, crate::ebpf::limiter::Direction::Upload);
        }

        eprintln!("  Result: removed {} orphan policy(ies)", orphan_ids.len());
        return Ok(());
    }

    // Stale state detected — count orphaned pins.
    let pin_dir = std::path::Path::new(crate::ebpf::limiter::PIN_DIR);
    let pin_count = std::fs::read_dir(pin_dir).map(|d| d.count()).unwrap_or(0);

    eprintln!("  State: STALE ({pin_count} orphaned pin file(s) detected)");
    eprintln!("  Cause: likely crash, SIGKILL, OOM, or partial upgrade");
    eprintln!("  Action: removing all pin files...");

    if verbose {
        if let Ok(entries) = std::fs::read_dir(pin_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    eprintln!("    - {name}");
                }
            }
        }
    }

    unpin_all()?;
    eprintln!("  Result: recovered ({pin_count} file(s) removed)");
    eprintln!("  Next: run 'zelynic strict-single <target> <rate>' to re-apply limits");
    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_status(verbose: bool, json: bool) -> Result<()> {
    use crate::ebpf::limiter::Limiter;

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    // Check if pin directory has any files. is_pinned() requires all 4 pins
    // (2 programs + 2 links), but stale pins from old versions may have
    // partial files. If partial → warn + suggest unstrict-all.
    if !pin_dir_has_files() {
        if json {
            println!(
                "{}",
                serde_json::json!({"watchdog": "clean", "active_limits": 0, "limits": []})
            );
        } else {
            println!("No active limits.");
        }
        return Ok(());
    }

    if !Limiter::is_pinned() {
        if json {
            println!(
                "{}",
                serde_json::json!({"error": "stale pins detected", "hint": "run 'zelynic recover'"})
            );
        } else {
            println!("Stale BPF pin files detected (partial state from old version).");
            println!("Run 'zelynic unstrict-all' to clean up, then re-apply limits.");
        }
        return Ok(());
    }

    let mut limiter = Limiter::open_pinned(verbose)?;
    limiter.refresh_identity();
    if json {
        limiter.print_status_json()?;
    } else {
        limiter.print_status();
    }
    Ok(())
}

#[cfg(feature = "ebpf")]
fn handle_list_apps(json: bool) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;
    use colored::Colorize;

    let mut identity = IdentityMap::new();
    let count = identity.refresh();

    let mut entries: Vec<_> = identity.all().into_iter().collect();
    entries.sort_by(|a, b| a.comm.cmp(&b.comm));
    entries.retain(|e| !e.comm.is_empty());

    if json {
        let apps: Vec<_> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "process": e.comm,
                    "cgroup_id": e.cgroup_id,
                    "uid": e.uid,
                })
            })
            .collect();
        println!("{}", serde_json::json!({"total": count, "apps": apps}));
        return Ok(());
    }

    println!("{}", "━━━ Apps with cgroup IDs ━━━".bold());
    println!("  {} cgroups resolved\n", count);
    println!("  {:<30} {:>10} {:>8}", "PROCESS", "CGROUP ID", "UID");
    println!("  {}", "─".repeat(50));

    for id in entries {
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
fn handle_observe(live: Option<&str>, cgroup: Option<u32>, verbose: bool) -> Result<()> {
    use crate::ebpf::loader::Observer;
    use crate::terminal;
    use std::time::Duration;

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let duration_secs = match live {
        Some(s) => crate::ebpf::limiter::parse_time_duration(s)?,
        None => 0, // forever
    };

    let mut observer = Observer::attach()?;
    observer.refresh_identity();
    if verbose {
        eprintln!("[ebpf] {} cgroups resolved", observer.identity().len());
    }

    // Establish baseline
    let _ = observer.poll_and_summarize()?;

    let duration = if duration_secs > 0 {
        Duration::from_secs(duration_secs)
    } else {
        Duration::ZERO // forever
    };

    terminal::run_alt(Duration::from_secs(1), duration, || {
        let summary = observer.poll_and_summarize().unwrap_or_default();
        println!("━━━ zelynic Observe (press q/ESC to quit) ━━━\n");
        if let Some(cg) = cgroup {
            summary.print_filtered(observer.identity(), cg);
        } else {
            summary.print(observer.identity());
        }
    });

    observer.detach();
    Ok(())
}

/// Handle `zelynic top` — snapshot or live box mode.
///
/// Default: 10s snapshot (prints once, exits).
/// --live: box mode, in-place refresh, accumulate, q/ESC to quit.
/// --live 3m: box mode for 3 minutes, then exit.
#[cfg(feature = "ebpf")]
fn handle_top(
    duration: Option<&str>,
    limit: usize,
    live: Option<&str>,
    _verbose: bool,
) -> Result<()> {
    use crate::ebpf::loader::Observer;
    use crate::terminal;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let mut observer = Observer::attach()?;
    observer.refresh_identity();

    // Cumulative totals per cgroup (accumulated across all polls)
    let mut cumulative: HashMap<u32, (u64, u64, u64)> = HashMap::new();

    // First poll to establish baseline
    let _ = observer.poll_and_summarize()?;

    if let Some(live_str) = live {
        // Live box mode
        let duration_secs = crate::ebpf::limiter::parse_time_duration(live_str)?;
        let dur = if duration_secs > 0 {
            Duration::from_secs(duration_secs)
        } else {
            Duration::ZERO // forever
        };

        terminal::run_alt(Duration::from_secs(5), dur, || {
            let summary = observer.poll_and_summarize().unwrap_or_default();
            for c in &summary.cgroups {
                let entry = cumulative.entry(c.cgroup_id).or_insert((0, 0, 0));
                entry.0 += c.ingress_bytes;
                entry.1 += c.bytes;
                entry.2 += c.packets + c.ingress_packets;
            }
            println!("━━━ zelynic Top — LIVE (press q/ESC to quit) ━━━\n");
            print_top_table(&cumulative, limit, observer.identity(), "accumulated");
        });
    } else {
        // Snapshot mode
        let dur_secs = match duration {
            Some(s) => crate::ebpf::limiter::parse_time_duration(s)?,
            None => 10,
        };

        eprintln!("━━━ zelynic Top — sampling for {dur_secs}s ━━━");
        eprintln!("  (collecting traffic data...)\n");

        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(dur_secs) {
            std::thread::sleep(Duration::from_millis(500));
            let summary = observer.poll_and_summarize()?;
            for c in &summary.cgroups {
                let entry = cumulative.entry(c.cgroup_id).or_insert((0, 0, 0));
                entry.0 += c.ingress_bytes;
                entry.1 += c.bytes;
                entry.2 += c.packets + c.ingress_packets;
            }
        }

        print_top_table(
            &cumulative,
            limit,
            observer.identity(),
            &format!("{dur_secs}s sample"),
        );
    }

    observer.detach();
    Ok(())
}

/// Print sorted top talkers table from cumulative data.
#[cfg(feature = "ebpf")]
fn print_top_table(
    cumulative: &std::collections::HashMap<u32, (u64, u64, u64)>,
    limit: usize,
    identity: &crate::ebpf::identity::IdentityMap,
    mode: &str,
) {
    use colored::Colorize;

    let mut talkers: Vec<(u32, u64, u64, u64, u64)> = cumulative
        .iter()
        .map(|(cg, (dl, ul, pkt))| (*cg, *dl, *ul, dl + ul, *pkt))
        .filter(|(_, _, _, total, _)| *total > 0)
        .collect();

    talkers.sort_by_key(|t| std::cmp::Reverse(t.3));

    if talkers.is_empty() {
        println!("  (no traffic yet — waiting...)\n");
        return;
    }

    let shown = talkers.len().min(limit);
    println!("━━━ Top {shown} Bandwidth Consumers ({mode}) ━━━");
    println!();
    println!(
        "  {:>3}  {:<28} {:>12} {:>12} {:>12}",
        "#", "CGROUP", "DOWNLOAD", "UPLOAD", "TOTAL"
    );
    println!("  {}", "─".repeat(73));

    let mut top_proc_name: Option<String> = None;
    let mut grand_total_pkt: u64 = 0;

    for (i, (cgroup_id, dl_bytes, ul_bytes, total, total_pkt)) in
        talkers.iter().take(limit).enumerate()
    {
        let label = identity.label(*cgroup_id);
        grand_total_pkt += total_pkt;

        println!(
            "  {:>3}  {:<28} {:>12} {:>12} {:>12}",
            i + 1,
            label,
            crate::ebpf::limiter::format_bytes(*dl_bytes),
            crate::ebpf::limiter::format_bytes(*ul_bytes),
            crate::ebpf::limiter::format_bytes(*total),
        );

        if i == 0 {
            top_proc_name = label
                .split('(')
                .nth(1)
                .and_then(|s| s.strip_suffix(')'))
                .filter(|s| !s.is_empty() && *s != "unknown")
                .map(|s| s.to_string());
        }
    }

    println!();
    println!("  {grand_total_pkt} packets total\n");

    if let Some(proc_name) = top_proc_name {
        println!("  {} Top consumer: {proc_name}", "→".yellow().bold());
        println!("  Limit it: sudo zelynic strict-single {proc_name} 100kb\n");
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
