// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Backend command handlers (Wolf Architecture — eBPF only).

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::{generate as generate_completion, Shell};

/// Handle `zelynic backend` (no subcommand) — print backend info.
pub(crate) fn handle_backend_info() -> Result<()> {
    use colored::Colorize;

    let report = crate::capabilities::detect();

    println!("{}", "━━━ zelynic Backend Info ━━━".bold());
    println!();
    println!("  Architecture: Wolf (pure eBPF)");
    println!("  Kernel:       {}", report.system.kernel);
    println!(
        "  cgroup v2:    {}",
        if report.system.cgroup_v2 {
            "YES".green().bold()
        } else {
            "NO".red().bold()
        }
    );
    println!(
        "  BPF fs:       {}",
        if report.system.bpf_fs_mounted {
            "YES".green().bold()
        } else {
            "NO".red().bold()
        }
    );
    println!(
        "  eBPF:         {}",
        if report.ebpf_supported {
            "SUPPORTED".green().bold()
        } else {
            "NOT SUPPORTED".red().bold()
        }
    );

    if report.ebpf_supported {
        println!();
        println!(
            "  {} `zelynic ebpf check` for detailed diagnostics",
            "Run:".cyan()
        );
    }

    Ok(())
}

/// Handle `zelynic backend doctor [--json]`.
pub(crate) fn handle_doctor(json: bool) -> Result<()> {
    crate::capabilities::run_doctor(json)
}

/// Handle `zelynic completions <shell>`.
pub(crate) fn handle_completions(shell: &str) -> Result<()> {
    let shell = shell.to_lowercase();
    let shell_type = match shell.as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "elvish" => Shell::Elvish,
        "powershell" => Shell::PowerShell,
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown shell '{}'. Supported: bash, zsh, fish, elvish, powershell",
                shell
            ))
        }
    };

    let mut cmd = crate::cli::Cli::command();
    generate_completion(shell_type, &mut cmd, "zelynic", &mut std::io::stdout());
    Ok(())
}

/// Handle `zelynic man` — generate man page.
pub(crate) fn generate_man_page() -> Result<()> {
    let cmd = crate::cli::Cli::command();
    let man = clap_mangen::Man::new(cmd);
    man.render(&mut std::io::stdout())?;
    Ok(())
}
