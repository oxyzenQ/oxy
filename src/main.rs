// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
/// zelynic — Per-app network rate limiter for Linux
///
/// Limit any app's download/upload speed using eBPF. Pure kernel enforcement.
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

fn main() {
    if let Err(e) = try_main() {
        // Print error without the default "Error:" prefix from Rust runtime.
        // If the error message already starts with "Warning:", keep it as-is.
        let msg = format!("{e}");
        if msg.starts_with("Warning:") || msg.starts_with("warning:") {
            eprintln!("{msg}");
        } else {
            eprintln!("zelynic: {msg}");
        }
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
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
