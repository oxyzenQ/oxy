// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use clap::{Parser, Subcommand};

/// zelynic — Per-app network rate limiter for Linux
///
/// Limit any app's download/upload speed using eBPF. Pure kernel enforcement,
/// no tc/nft. Requires kernel 5.13+ and root.
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
    #[arg(long, global = true, help = "Disable colored output")]
    pub no_color: bool,

    /// Verbose/debug output
    #[arg(short = 'v', long = "verbose", global = true)]
    pub verbose: bool,

    /// Output as JSON (where applicable)
    #[arg(long, global = true)]
    pub print_json: bool,

    /// Show comprehensive help
    #[arg(long = "help-all", global = false)]
    pub help_all: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Limit a single app's network speed
    ///
    /// Examples:
    ///   zelynic strict-single brave 100kb              # both dl+ul = 100kb
    ///   zelynic strict-single brave -d 100kb           # download only
    ///   zelynic strict-single brave -u 500kb           # upload only
    ///   zelynic strict-single firefox -d 1mb -u 500kb  # both, different rates
    #[command(name = "strict-single")]
    StrictSingle {
        /// Target: process name (e.g., brave) or cgroup ID (e.g., 73386)
        target: String,

        /// Rate for both download+upload (e.g., 100kb, 1mb). Use -d/-u for per-direction.
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit (e.g., 100kb, 1mb)
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit (e.g., 100kb, 1mb)
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Allow rates below 1 kb (dangerous)
        #[arg(long)]
        allow_dangerous: bool,

        /// Force limit on dangerous/system targets (root, systemd, kthreadd, etc.)
        #[arg(long)]
        force: bool,
    },

    /// Limit multiple apps sharing one rate (group limit)
    ///
    /// All apps in the group collectively share the rate limit.
    /// If one app downloads at full rate, others get nothing.
    ///
    /// Examples:
    ///   zelynic strict-multi brave:curl:pacman 1mb              # both dl+ul = 1mb
    ///   zelynic strict-multi brave:curl -d 1mb -u 500kb         # per-direction
    #[command(name = "strict-multi")]
    StrictMulti {
        /// Targets separated by colons (e.g., brave:curl:pacman)
        targets: String,

        /// Rate for both download+upload (e.g., 1mb). Use -d/-u for per-direction.
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit (shared across all targets)
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit (shared across all targets)
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Allow rates below 1 kb (dangerous)
        #[arg(long)]
        allow_dangerous: bool,

        /// Force limit on dangerous/system targets (root, systemd, kthreadd, etc.)
        #[arg(long)]
        force: bool,
    },

    /// Limit ALL user apps from list-apps
    ///
    /// Applies the same rate to all non-system apps.
    /// System apps (root, systemd, kthreadd, etc.) are excluded by default.
    /// Use --force to include system apps.
    ///
    /// Examples:
    ///   zelynic all-limit 500kb              # limit all user apps
    ///   zelynic all-limit -d 1mb -u 500kb    # per-direction
    #[command(name = "all-limit")]
    AllLimit {
        /// Rate for both download+upload (e.g., 500kb, 1mb)
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Allow rates below 1 kb (dangerous)
        #[arg(long)]
        allow_dangerous: bool,

        /// Include system/dangerous targets (root, systemd, kthreadd, etc.)
        #[arg(long)]
        force: bool,
    },

    /// Remove rate limit from a target
    ///
    /// Example: zelynic unstrict brave
    #[command(name = "unstrict")]
    Unstrict {
        /// Target: process name or cgroup ID
        target: String,
    },

    /// Remove ALL rate limits (emergency reset)
    #[command(name = "unstrict-all")]
    UnstrictAll,

    /// Show active limits and watchdog status
    #[command(name = "status")]
    Status,

    /// List apps with their cgroup IDs
    #[command(name = "list-apps")]
    ListApps,

    /// Real-time traffic monitor (read-only)
    ///
    /// Shows per-cgroup traffic in real-time. No enforcement.
    #[command(name = "observe")]
    Observe {
        /// Print summary every N seconds
        #[arg(long, default_value = "5")]
        interval: u64,

        /// Duration in seconds (0 = until Ctrl+C)
        #[arg(long, default_value = "0")]
        duration: u64,
    },

    /// Check if your machine supports eBPF
    #[command(name = "doctor")]
    Doctor,

    /// Generate shell completions
    Completions {
        /// Shell: bash, zsh, fish, elvish, powershell
        shell: String,
    },

    /// Generate man page
    Man,
}
