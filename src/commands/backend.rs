// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Backend utility handlers (completions + man page).

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::{generate as generate_completion, Shell};

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
