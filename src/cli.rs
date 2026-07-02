// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use clap::{Args, Parser, Subcommand};

/// zelynic — Pure eBPF network rate limiter for Linux
///
/// Wolf Architecture: single hooking layer (eBPF), no tc/nft/systemd-wrapper.
/// Requires kernel 5.13+ (cgroup v2 + cgroup.id file).
#[derive(Parser, Debug)]
#[command(
    name = "zelynic",
    version,
    author = "rezky_nightky (oxyzenQ)",
    about = env!("CARGO_PKG_DESCRIPTION"),
    long_about = None,
    disable_version_flag = true,
    propagate_version = true,
    arg_required_else_help = false,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Print detailed package information
    #[arg(short = 'i', long = "info", global = false)]
    pub info: bool,

    /// Print complete version and build information
    #[arg(short = 'V', long = "version", global = false)]
    pub version: bool,

    /// Check the latest upstream GitHub release
    #[arg(long = "check-update", alias = "check-updated", global = false)]
    pub check_update: bool,

    /// Disable colored output
    ///
    /// Alternatively, set NO_COLOR=1 environment variable.
    #[arg(long, global = true, help = "Disable colored output")]
    pub no_color: bool,

    /// Show comprehensive help with all commands, options, and examples
    #[arg(
        long = "help-all",
        global = false,
        help = "Show comprehensive help with all commands and examples"
    )]
    pub help_all: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// eBPF observer + limiter engine
    ///
    /// Real-time kernel-level traffic observation and enforcement using eBPF.
    /// Pure eBPF — no tc, no nft, no cgroup-wrapper.
    #[command(hide = false)]
    Ebpf {
        #[command(subcommand)]
        command: Option<EbpfCommands>,
    },

    /// Show backend information (eBPF support, kernel version, etc.)
    Backend {
        #[command(subcommand)]
        command: Option<BackendCommands>,
    },

    /// Generate shell completions
    Completions {
        /// Shell type (bash, zsh, fish, elvish, powershell)
        shell: String,
    },

    /// Generate man page
    Man,
}

/// eBPF observer + limiter subcommands.
#[derive(Debug, Subcommand)]
pub enum EbpfCommands {
    /// Check if the system supports eBPF observer
    Check,

    /// Start real-time traffic observer (requires root + --features ebpf)
    Observe {
        /// Duration in seconds (0 = until Ctrl+C)
        #[arg(long, default_value = "0")]
        duration: u64,

        /// Print summary every N seconds
        #[arg(long, default_value = "5")]
        interval: u64,
    },

    /// Enforce per-cgroup rate limits via eBPF token bucket (requires root + --features ebpf)
    ///
    /// Pure eBPF enforcement — no tc, no nft, no cgroup-wrapper.
    /// Policies are ephemeral: they persist only while this command runs.
    ///
    /// Safety: BPF self-destruct watchdog auto-disables enforcement if
    /// zelynic crashes (default 30s timeout). Use --watchdog to adjust.
    ///
    /// Examples:
    ///   zelynic ebpf enforce --limit 73386:1MB/s
    ///   zelynic ebpf enforce --limit firefox:500KB/s --limit unbound:100KB/s
    ///   zelynic ebpf enforce --limit firefox:1MB/s --stats-interval 5 --watchdog 60
    Enforce {
        /// Rate limit policy: <cgroup_id|process_name>:<rate>
        /// Repeatable. e.g., --limit firefox:1MB/s --limit 73386:500KB/s
        #[arg(long = "limit", value_name = "TARGET:RATE")]
        limits: Vec<String>,

        /// Print enforcement stats every N seconds (0 = only on exit)
        #[arg(long, default_value = "5")]
        stats_interval: u64,

        /// Duration in seconds (0 = until Ctrl+C)
        #[arg(long, default_value = "0")]
        duration: u64,

        /// Watchdog timeout in seconds. If zelynic crashes, BPF auto-disables
        /// after this many seconds. Default: 30. Minimum: 5.
        #[arg(long, default_value = "30")]
        watchdog: u64,

        /// Allow rates below minimum (1 KB/s). Dangerous — may brick the
        /// target cgroup's network access. Use with caution.
        #[arg(long)]
        allow_dangerous: bool,
    },
}

#[derive(Debug, Args)]
pub struct BackendDoctorArgs {
    /// Output Backend Doctor report as JSON
    #[arg(long)]
    pub json: bool,
}

/// Backend subcommands.
#[derive(Debug, Subcommand)]
pub enum BackendCommands {
    /// Show detailed read-only host capability diagnostics and backend scoring
    Doctor(BackendDoctorArgs),
}
