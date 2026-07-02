// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
/// zelynic — Pure eBPF network rate limiter for Linux (Wolf Architecture)
///
/// Per-process network bandwidth control using eBPF. No tc, no nft, no
/// systemd-wrapper. Single hooking layer: cgroup_skb/egress + ingress.
mod capabilities;
mod cli;
mod commands;
mod ebpf;
mod ebpf_legacy;
mod info;
mod update;

use anyhow::Result;
use clap::Parser;

use cli::Cli;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "-v" || args[1] == "--ver") {
        info::print_version();
        return Ok(());
    }

    let cli = Cli::parse();

    if cli.help_all {
        commands::help::print_help_all();
        return Ok(());
    }

    if cli.no_color || std::env::var("NO_COLOR").is_ok() {
        colored::control::set_override(false);
    }

    if cli.version {
        info::print_info();
        return Ok(());
    }

    if cli.check_update {
        update::check_update(info::VERSION).map_err(anyhow::Error::msg)?;
        return Ok(());
    }

    if cli.info {
        info::print_info();
        return Ok(());
    }

    commands::dispatch(cli)
}
