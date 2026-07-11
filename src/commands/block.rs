// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Block command handlers — block apps from internet entirely.

use anyhow::Result;

use crate::ebpf::limiter::{Limiter, RateSpec, Target};

/// Block a single app from the internet.
pub fn handle_block_single(target_str: &str, force: bool, verbose: bool) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let _lock = crate::ebpf::lock::acquire()?;
    super::check_dangerous_target(target_str, force)?;

    Limiter::attach(verbose)?;

    let mut limiter = Limiter::open_pinned(verbose)?;
    let target = Target::parse(target_str);

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    let applied = limiter.apply_single(&target, &rates)?;
    if applied == 0 {
        eprintln!("No cgroup found for '{target_str}'. Nothing to block.");
        return Ok(());
    }

    eprintln!("Blocked '{target_str}' from internet ({applied} policies, active in background)");
    eprintln!("Run 'zelynic unblock {target_str}' to restore access, 'zelynic status' to check.");
    Ok(())
}

/// Block multiple apps from the internet.
pub fn handle_block_multi(targets_str: &str, force: bool, verbose: bool) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let _lock = crate::ebpf::lock::acquire()?;

    let targets: Vec<Target> = targets_str.split(':').map(Target::parse).collect();
    for t in &targets {
        if let Target::ProcessName(name) = t {
            super::check_dangerous_target(name, force)?;
        }
    }

    Limiter::attach(verbose)?;
    let mut limiter = Limiter::open_pinned(verbose)?;

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    let applied = limiter.apply_group(&targets, &rates)?;
    if applied == 0 {
        eprintln!("No cgroups found for '{targets_str}'. Nothing to block.");
        return Ok(());
    }

    eprintln!("Blocked '{targets_str}' from internet ({applied} policies, active in background)");
    eprintln!("Run 'zelynic unblock <target>' to restore access.");
    Ok(())
}

/// Block ALL user apps from the internet.
pub fn handle_block_all(force: bool, verbose: bool) -> Result<()> {
    use crate::ebpf::identity::IdentityMap;

    if !nix::unistd::geteuid().is_root() {
        eprintln!("zelynic requires root. Run with sudo.");
        return Err(anyhow::anyhow!("root required"));
    }

    let _lock = crate::ebpf::lock::acquire()?;

    let mut identity = IdentityMap::new();
    identity.refresh();

    let user_apps: Vec<_> = identity
        .all()
        .into_iter()
        .filter(|e| !e.comm.is_empty() && e.uid > 0)
        .collect();

    let system_apps: Vec<_> = identity
        .all()
        .into_iter()
        .filter(|e| !e.comm.is_empty() && e.uid == 0)
        .collect();

    if !force && !system_apps.is_empty() {
        eprintln!("Blocking {} user app(s)", user_apps.len());
        eprintln!(
            "Skipped {} system app(s) (use --force to include):",
            system_apps.len()
        );
        for app in system_apps.iter().take(20) {
            eprintln!("  - {}", app.comm);
        }
    }

    let targets: Vec<Target> = if force {
        identity
            .all()
            .into_iter()
            .filter(|e| !e.comm.is_empty())
            .map(|e| Target::CgroupId(e.cgroup_id))
            .collect()
    } else {
        user_apps
            .iter()
            .map(|e| Target::CgroupId(e.cgroup_id))
            .collect()
    };

    if targets.is_empty() {
        eprintln!("No apps to block.");
        return Ok(());
    }

    Limiter::attach(verbose)?;
    let mut limiter = Limiter::open_pinned(verbose)?;

    let rates = RateSpec {
        download: Some(0),
        upload: Some(0),
    };
    let applied = limiter.apply_group(&targets, &rates)?;
    eprintln!(
        "Blocked {} app(s) from internet ({applied} policies, active in background)",
        targets.len()
    );
    eprintln!("Run 'zelynic unstrict-all' to restore all access.");
    Ok(())
}
