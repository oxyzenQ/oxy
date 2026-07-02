// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use clap::{Args, Parser, Subcommand, ValueEnum};

/// zelynic - Per-process network shaping and bandwidth control for Linux
///
/// Manage network bandwidth per process using Linux traffic control (tc) and cgroups.
/// Requires root privileges for bandwidth limiting operations.
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

    /// Network interface to use
    ///
    /// Defaults to the first non-loopback interface. Use this to explicitly
    /// specify which interface to monitor and shape (e.g., eth0, wlan0).
    /// Use without a value (--iface) to list available interfaces.
    #[arg(
        long,
        global = true,
        value_name = "INTERFACE",
        num_args = 0..=1,
        help = "Network interface to use (no value = list available)"
    )]
    pub iface: Option<Option<String>>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List network bandwidth usage per process
    ///
    /// Displays all processes with active network connections along with
    /// their bandwidth consumption statistics.
    ///
    /// Use --live for real-time rate monitoring (like htop for bandwidth).
    /// Use --verbose to see individual socket connections per process.
    List {
        /// Show all programs/ports with bandwidth usage
        #[arg(long = "usage-all")]
        usage_all: bool,

        /// Show programs sorted by highest to lowest bandwidth usage
        #[arg(long = "high-to-low-usage-net")]
        high_to_low: bool,

        /// Output results as JSON for scripting integration
        #[arg(long = "json")]
        json: bool,

        /// Live mode: continuously refresh with real-time rates
        ///
        /// Enters TUI mode with auto-refresh. Shows per-process
        /// bandwidth rates (bytes/sec) instead of cumulative totals.
        /// Press 'q' or Ctrl+C to exit.
        ///
        /// Accepts optional interval value:
        ///   --live          # 1 second default
        ///   --live 2        # 2 second interval
        #[arg(long = "live", num_args = 0..=1, value_name = "SECONDS")]
        live: Option<Option<u64>>,

        /// Refresh interval in seconds for live mode [default: 1]
        #[arg(long = "interval", value_name = "SECONDS")]
        interval: Option<u64>,

        /// Verbose mode: show individual socket connections
        ///
        /// Displays per-connection breakdown including remote IP, port,
        /// protocol (TCP/UDP), and bytes transferred for each socket.
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
    },

    /// Set bandwidth limits (strict) for a specific process
    ///
    /// Applies download and/or upload speed limits to the target process
    /// using Linux traffic control (tc) with HTB qdisc and cgroups.
    ///
    /// Supported units: byte/bs, kb, mb, gb, kbit, mbit, gbit
    ///
    /// Use --preset for common profiles instead of manual rates:
    ///   gaming     - 50mb/50mb (prioritizes low latency)
    ///   streaming  - 10mb/5mb  (balanced for video calls)
    ///   background - 500kb/100kb (minimal, for downloads)
    ///
    /// Examples:
    ///   zelynic strict -d 500kb -u 500kb brave
    ///   zelynic strict -d 1mb firefox               # Download only
    ///   zelynic strict -u 250kb 1234                # Upload only
    ///   zelynic strict --preset gaming discord
    ///   zelynic strict --preset background steam
    #[command(verbatim_doc_comment)]
    Strict {
        /// Download speed limit (e.g., 500kb, 1mb, 2gb, 100byte)
        #[arg(short = 'd', long = "download", allow_hyphen_values = true)]
        download: Option<String>,

        /// Upload speed limit (e.g., 500kb, 1mb, 2gb, 100byte)
        #[arg(short = 'u', long = "upload", allow_hyphen_values = true)]
        upload: Option<String>,

        /// Preset bandwidth profile (conflicts with -d/-u)
        ///
        /// Available presets:
        /// - gaming:     50mb down / 50mb up  (low latency priority)
        /// - streaming:  10mb down / 5mb up   (balanced for video)
        /// - background: 500kb down / 100kb up (minimal, deprioritized)
        #[arg(long = "preset", value_name = "PROFILE", group = "preset_group")]
        preset: Option<String>,

        /// Print strict backend diagnostics while applying the limit
        ///
        /// This keeps normal strict behavior but emits cgroup v2, nftables,
        /// tc details, and selected-PID match reasons needed to debug backend
        /// failures on a real Linux host.
        #[arg(long = "diagnose", alias = "diag")]
        diagnose: bool,

        /// [hidden/experimental] Pre-launch cgroup wrapper alias.
        ///
        /// Launches child inside Zelynic cgroup before sockets are created,
        /// then applies the same nft/tc policy. This is an alias for the
        /// hidden `strict-run-lab` command. It is NOT stable.
        ///
        /// When set, the positional TARGET and all trailing args become the
        /// child command (pass after `--`):
        ///   zelynic strict --run-lab --diagnose -d 100kb -- aria2c https://example.com/f.iso
        #[arg(long = "run-lab", hide = true)]
        run_lab: bool,

        /// Target process name or PID (name matching is conservative; use PID for exact targeting)
        ///
        /// In normal mode: exactly one value (process name or PID).
        /// In --run-lab mode: child command and args (pass after `--`).
        #[arg(value_name = "TARGET", num_args = 1..)]
        target: Vec<String>,
    },

    /// Remove all bandwidth limits from a process
    ///
    /// Removes all tc classes, filters, and cgroup rules that were applied
    /// to the target process, restoring full bandwidth access.
    #[command(verbatim_doc_comment)]
    Unstrict {
        /// Target process name or PID to release from bandwidth limits
        target: String,
    },

    /// Refresh an existing limit after a target process respawns
    ///
    /// Discovers current PIDs for an already-limited target and moves any
    /// missing live PIDs into the existing target cgroup. This does not create
    /// a new limit and does not duplicate nftables or tc rules.
    ///
    /// Examples:
    ///   zelynic refresh brave
    ///   zelynic refresh 1234
    #[command(verbatim_doc_comment)]
    Refresh {
        /// Target process name or PID that already has an active strict limit
        target: String,
    },

    /// Experimental groundwork for launching a command in a future systemd scope
    ///
    /// Examples:
    ///   zelynic run --dry-run -d 500kbit -u 500kbit -- helium
    ///   zelynic run --execute -d 500kbit -u 500kbit -- helium
    #[command(verbatim_doc_comment)]
    Run {
        /// Show the planned systemd scope wrapper without launching anything
        #[arg(long = "dry-run", conflicts_with = "execute")]
        dry_run: bool,

        /// Experimental live execution opt-in; currently parsed but not implemented
        #[arg(long = "execute", conflicts_with = "dry_run")]
        execute: bool,

        /// Root-only system-scope live probe; reports findings without applying limits
        #[arg(long = "probe-live", requires = "execute")]
        probe_live: bool,

        /// Explicit future live attach gate; hard-blocked and non-mutating
        #[arg(long = "attach-live", requires = "execute", requires = "probe_live")]
        attach_live: bool,

        /// Experimental single-PID move attach consent gate (v2.7, HARD-BLOCKED)
        #[arg(
            long = "experimental-single-pid-attach",
            requires = "execute",
            requires = "probe_live",
            requires = "attach_live"
        )]
        experimental_single_pid_attach: bool,

        /// Acknowledge future PID movement experiments
        #[arg(
            long = "i-understand-this-moves-pids",
            requires = "execute",
            requires = "probe_live",
            requires = "attach_live"
        )]
        i_understand_this_moves_pids: bool,

        #[arg(
            long = "rollback-required",
            requires = "execute",
            requires = "probe_live",
            requires = "attach_live"
        )]
        rollback_required: bool,

        /// First real-write experiment: mkdir-only cgroup preparation with cleanup (v2.8 phase 2b)
        #[arg(
            long = "mkdir-live",
            requires = "execute",
            requires = "probe_live",
            requires = "attach_live",
            requires = "experimental_single_pid_attach",
            requires = "i_understand_this_moves_pids",
            requires = "rollback_required"
        )]
        mkdir_live: bool,

        #[allow(dead_code)]
        /// Optional target name for state/cgroup naming; defaults to command basename
        #[arg(long = "target", value_name = "TARGET")]
        target: Option<String>,

        #[allow(dead_code)]
        /// Planning scope mode
        #[arg(long = "scope-mode", value_enum, default_value_t = RunScopeModeArg::User)]
        scope_mode: RunScopeModeArg,

        /// Download speed limit
        #[arg(short = 'd', long = "download", allow_hyphen_values = true)]
        download: Option<String>,

        /// Upload speed limit
        #[arg(short = 'u', long = "upload", allow_hyphen_values = true)]
        upload: Option<String>,

        /// Command to launch; pass after `--`
        #[arg(
            required = true,
            num_args = 1..,
            last = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },

    /// Show active bandwidth limits
    ///
    /// Displays all currently active bandwidth limits that were applied
    /// using the 'strict' command, showing target processes, limits,
    /// and interfaces.
    Status,

    /// Generate shell completions
    ///
    /// Outputs shell completion scripts for bash, zsh, fish, etc.
    /// Install by redirecting output to your shell's completions directory.
    ///
    /// Examples:
    ///   zelynic completions bash > /usr/share/bash-completion/completions/zelynic
    ///   zelynic completions zsh > /usr/local/share/zsh/site-functions/_zelynic
    ///   zelynic completions fish > ~/.config/fish/completions/zelynic.fish
    #[command(verbatim_doc_comment)]
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, elvish, powershell)
        shell: String,
    },

    /// Generate man page
    ///
    /// Outputs a man page in roff format for zelynic.
    /// Install by redirecting output to your man page directory.
    ///
    /// Examples:
    ///   zelynic man > /usr/share/man/man1/zelynic.1
    ///   zelynic man | gzip > /usr/share/man/man1/zelynic.1.gz
    #[command(verbatim_doc_comment)]
    Man,

    /// Clean up orphaned bandwidth limits
    ///
    /// Removes tc classes, filters, and cgroups for processes that have
    /// already exited. Run this periodically or when you suspect stale
    /// rules are accumulating.
    #[command(verbatim_doc_comment)]
    Clean {
        /// Perform emergency cleanup: remove ALL state, rules, and cgroups.
        /// Use this when normal unstrict fails (e.g., target process has exited).
        #[arg(
            long,
            help = "Remove ALL state, nftables rules, tc objects, and cgroups"
        )]
        all: bool,
    },

    /// Show bandwidth usage history
    ///
    /// Displays historical bandwidth snapshots logged over time.
    /// Use with --snapshot to record current state for later analysis.
    ///
    /// Examples:
    ///   zelynic log              # Show recent history
    ///   zelynic log --snapshot     # Record current state
    ///   zelynic log --last 1h      # Show last hour
    ///   zelynic log --last 24h     # Show last 24 hours
    #[command(verbatim_doc_comment)]
    Log {
        /// Record current bandwidth snapshot
        #[arg(long = "snapshot")]
        snapshot: bool,

        /// Show history for last N hours (e.g., 1h, 24h)
        #[arg(long = "last", value_name = "HOURS")]
        last: Option<u64>,

        /// Output as JSON for analysis
        #[arg(long = "json")]
        json: bool,
    },

    /// Manage named bandwidth profiles
    ///
    /// Save and load bandwidth limit profiles for quick application.
    /// Profiles persist across sessions and can be applied with a single command.
    ///
    /// Examples:
    ///   zelynic profile save background --dl 100kb --ul 100kb
    ///   zelynic profile save streaming --dl 5mb --ul 2mb
    ///   zelynic profile list
    ///   zelynic profile apply background firefox
    ///   zelynic profile delete background
    #[command(verbatim_doc_comment)]
    Profile {
        /// Profile subcommand
        #[command(subcommand)]
        command: ProfileCommands,
    },

    /// Quality of Service (QoS) priority-based bandwidth shaping
    ///
    /// Assign processes a priority tier instead of hard limits. High priority
    /// processes get bandwidth first; idle bandwidth from low-priority processes
    /// redistributes to high-priority ones automatically.
    ///
    /// This solves the "large download + browsing" use case: set wget to low
    /// priority and browser to high — browser stays fast, wget gets leftovers.
    ///
    /// Examples:
    ///   zelynic qos high brave        # High priority for browser
    ///   zelynic qos low wget           # Low priority for download
    ///   zelynic qos status             # Show current QoS assignments
    ///   zelynic qos reset              # Clear all QoS rules
    #[command(verbatim_doc_comment)]
    Qos {
        /// QoS subcommand
        #[command(subcommand)]
        command: QosCommands,
    },

    /// Watch bandwidth and alert when thresholds are exceeded
    ///
    /// Monitor a process and send desktop notification (or stderr fallback)
    /// when bandwidth exceeds specified threshold. Useful for background
    /// download monitoring without keeping --live open.
    ///
    /// Examples:
    ///   zelynic watch --alert 500kb wget     # Alert when rate > 500KB/s
    ///   zelynic watch --alert 5mb firefox   # Alert when rate > 5MB/s
    ///   zelynic watch --alert 100mb -i 30    # Check every 30 seconds
    #[command(verbatim_doc_comment)]
    Watch {
        /// Alert threshold as bandwidth rate (e.g., 500kb, 5mb, 100mb)
        #[arg(
            short = 'a',
            long,
            value_name = "RATE",
            required = true,
            allow_hyphen_values = true
        )]
        alert: String,
        /// Process to watch (name or PID)
        #[arg(value_name = "PROCESS")]
        target: String,
        /// Check interval in seconds
        #[arg(short, long, default_value = "10")]
        interval: u64,
        /// Desktop notification command (default: notify-send)
        #[arg(long, value_name = "CMD")]
        notify_cmd: Option<String>,
    },

    /// Auto-throttle: background daemon mode
    ///
    /// Runs continuously in the background, monitoring total bandwidth usage
    /// and automatically applying limits when bandwidth exceeds thresholds.
    /// Perfect for unattended systems that need automatic bandwidth management.
    ///
    /// Examples:
    ///   zelynic auto --download 100mb --upload 50mb     # Limit when > threshold
    ///   zelynic auto --download 80mb --kill firefox    # Kill heavy users
    ///   zelynic auto --daemon                          # Run as daemon
    #[command(verbatim_doc_comment)]
    Auto {
        /// Download threshold (e.g., 100mb, 1gb)
        #[arg(short = 'd', long, value_name = "RATE", allow_hyphen_values = true)]
        download: Option<String>,
        /// Upload threshold (e.g., 50mb, 100mb)
        #[arg(short = 'u', long, value_name = "RATE", allow_hyphen_values = true)]
        upload: Option<String>,
        /// Process to auto-limit when threshold exceeded
        #[arg(short, long, value_name = "PROCESS")]
        target: Option<String>,
        /// Kill process instead of limiting (when --target specified)
        #[arg(long, requires = "target")]
        kill: bool,
        /// Run as background daemon
        #[arg(long)]
        daemon: bool,
        /// Check interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
        /// Show auto-throttle daemon status
        #[arg(short, long)]
        status: bool,
    },

    /// Show live read-only network interface usage counters
    ///
    /// Displays a single read-only snapshot of network interface counters
    /// from /proc/net/dev. Requires --sample in this phase.
    ///
    /// This command is read-only: it does not block, throttle, enforce
    /// quotas, or mutate any system state.
    ///
    /// Examples:
    ///   zelynic usage --sample             # Single live snapshot (text)
    ///   zelynic usage --sample --json     # Single live snapshot (JSON)
    ///   zelynic usage --sample --delta    # Two-sample delta (text)
    ///   zelynic usage --sample --delta --json  # Two-sample delta (JSON)
    Usage {
        /// Perform a single live read-only snapshot of /proc/net/dev
        #[arg(long, required = true)]
        sample: bool,

        /// Output machine-readable JSON (requires --sample)
        ///
        /// When used with --sample, prints the usage snapshot as structured
        /// JSON instead of human-readable text. Single-shot only.
        #[arg(long, requires = "sample")]
        json: bool,

        /// Compute two-sample read-only delta (requires --sample)
        ///
        /// Reads /proc/net/dev twice with a 1-second wait between samples,
        /// computes per-interface byte deltas, and renders the result.
        /// Use --json to output machine-readable delta JSON.
        /// Fixed 1-second delta wait. No loop/watch mode. Read-only /proc/net/dev only.
        #[arg(long, requires = "sample")]
        delta: bool,

        // ---- v3.1 phase 6: hidden future-gated flags (parsed but hard-blocked). ----
        /// [design-gated] Report usage accumulated since session start.
        /// Not yet implemented. Requires ledger persistence.
        #[arg(long = "session", hide = true, requires = "sample")]
        #[allow(dead_code)]
        session: bool,

        /// [design-gated] Report usage accumulated since system boot.
        /// Not yet implemented. Requires ledger persistence + boot_id.
        #[arg(long = "since-boot", hide = true, requires = "sample")]
        #[allow(dead_code)]
        since_boot: bool,

        /// [design-gated] Filter usage output to a specific interface.
        /// Not yet implemented.
        #[arg(
            long = "interface",
            hide = true,
            requires = "sample",
            value_name = "NAME"
        )]
        #[allow(dead_code)]
        usage_interface: Option<String>,

        /// [design-gated] Report usage attributed to a specific target.
        /// Not yet implemented. Requires persistence + identity resolver.
        #[arg(
            long = "target",
            hide = true,
            requires = "sample",
            value_name = "TARGET"
        )]
        #[allow(dead_code)]
        usage_target: Option<String>,
    },

    /// [experimental] Pre-launch cgroup wrapper for strict traffic proof experiment.
    ///
    /// Launches a child process inside a Zelynic-managed cgroup before the child
    /// opens network sockets, then applies the same nft/tc policy. This tests
    /// whether pre-launch cgroup placement improves socket cgroupv2 matching.
    ///
    /// HIDDEN: this is an experimental lab command. Do NOT use in production.
    ///
    /// Examples:
    ///   zelynic strict-run-lab --diagnose --iface proton0 -d 100kb -- aria2c -x 1 -s 1 https://example.com/file.iso
    #[command(hide = true, verbatim_doc_comment)]
    StrictRunLab {
        /// Download speed limit (e.g., 500kb, 1mb, 100byte)
        #[arg(short = 'd', long = "download", allow_hyphen_values = true)]
        download: Option<String>,

        /// Upload speed limit (e.g., 500kb, 1mb, 100byte)
        #[arg(short = 'u', long = "upload", allow_hyphen_values = true)]
        upload: Option<String>,

        /// Print strict backend diagnostics while applying the limit
        #[arg(long = "diagnose", alias = "diag")]
        diagnose: bool,

        /// Command to launch; pass after `--`
        #[arg(
            required = true,
            num_args = 1..,
            last = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },

    /// [design-gated] Network ledger inspection and export (v3.1 phase 6).
    ///
    /// This subcommand is registered in the parser but hard-blocked at dispatch.
    /// It will be activated in a future phase after persistence is implemented.
    #[command(hide = true)]
    Ledger {
        /// Ledger subcommand (inspect, export)
        #[command(subcommand)]
        command: LedgerCommands,
    },

    /// Show backend information and capability checks
    ///
    /// Displays the active backend (tc/cgroup) and whether the system
    /// supports eBPF for future use. Use `zelynic backend doctor` for a
    /// detailed read-only capability matrix.
    Backend {
        /// Optional backend diagnostic command
        #[command(subcommand)]
        command: Option<BackendCommands>,
    },

    /// eBPF observer engine (experimental, requires --features ebpf)
    ///
    /// Real-time kernel-level traffic observation using eBPF.
    /// Observer only — no enforcement, no packet drop.
    #[command(hide = true)]
    Ebpf {
        #[command(subcommand)]
        command: Option<EbpfCommands>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RunScopeModeArg {
    /// Preview a user-scoped transient systemd unit
    User,
    /// Preview a system-scoped transient systemd unit
    System,
}

/// Backend diagnostics subcommands.
#[derive(Debug, Subcommand)]
pub enum BackendCommands {
    /// Show detailed read-only host capability diagnostics and backend scoring
    Doctor(BackendDoctorArgs),
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
    /// Examples:
    ///   zelynic ebpf enforce --limit 73386:1MB/s
    ///   zelynic ebpf enforce --limit firefox:500KB/s --limit unbound:100KB/s
    ///   zelynic ebpf enforce --limit firefox:1MB/s --stats-interval 5
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
    },
}

#[derive(Debug, Args)]
pub struct BackendDoctorArgs {
    /// Output Backend Doctor report as JSON
    #[arg(long)]
    pub json: bool,
}

/// Profile management subcommands.
#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    /// Save a new bandwidth profile
    Save {
        /// Profile name (e.g., background, streaming, gaming)
        name: String,
        /// Download limit (e.g., 100kb, 5mb, 1gb)
        #[arg(long = "dl", value_name = "RATE", allow_hyphen_values = true)]
        download: Option<String>,
        /// Upload limit (e.g., 100kb, 5mb, 1gb)
        #[arg(long = "ul", value_name = "RATE", allow_hyphen_values = true)]
        upload: Option<String>,
    },
    /// Apply a saved profile to a process
    Apply {
        /// Profile name to apply
        name: String,
        /// Target process name or PID
        target: String,
    },
    /// List all saved profiles
    List,
    /// Delete a saved profile
    Delete {
        /// Profile name to delete
        name: String,
    },
}

/// Ledger subcommands (v3.1 phase 6: design-gated, hard-blocked at dispatch).
#[derive(Debug, Subcommand)]
pub enum LedgerCommands {
    /// Display a human-readable ledger summary.
    #[command(hide = true)]
    Inspect {
        /// Output as JSON (requires schema_version 2+).
        #[arg(long, hide = true)]
        json: bool,
        /// [v3.1 phase 12] Read ledger from explicit file path (read-only).
        #[arg(long = "file", hide = true, value_name = "PATH")]
        file: Option<String>,
    },

    /// Export full ledger data as JSON.
    #[command(hide = true)]
    Export {
        /// Output as JSON.
        #[arg(long, hide = true)]
        json: bool,
        /// [v3.1 phase 16] Read ledger from explicit file path (read-only, stdout-only).
        #[arg(long = "file", hide = true, value_name = "PATH")]
        file: Option<String>,
    },
}

/// QoS priority management subcommands.
#[derive(Debug, Subcommand)]
pub enum QosCommands {
    /// Set high priority for a process
    ///
    /// High priority processes get bandwidth first.
    /// Idle bandwidth from low-priority processes redistributes here.
    High {
        /// Process name or PID to prioritize
        target: String,
    },
    /// Set low priority for a process
    ///
    /// Low priority processes get leftover bandwidth only.
    /// When bandwidth is scarce, these are throttled first.
    Low {
        /// Process name or PID to deprioritize
        target: String,
    },
    /// Show current QoS assignments
    Status,
    /// Reset all QoS rules
    Reset,
}

/// v3.1 phase 6: design-gated safety disclaimer output.
///
/// Returns the multi-line rejection message printed when a design-gated
/// command is encountered at dispatch time. Each line is a separate safety
/// disclaimer confirming the command is blocked.
pub(crate) const DESIGN_GATED_DISCLAIMERS: &[&str] = &[
    "design-gated: this command is not yet implemented",
    "no live resolver: no process scanning or identity resolution",
    "no ledger persistence: no file read/write for ledger data",
    "no filesystem write: no files are written to disk",
    "no enforcement: no blocking, throttling, or quota active",
    "no network blocking: no traffic blocking or shaping",
    "no nft/tc mutation: no nftables or traffic control changes",
    "no cgroup mutation: no cgroup writes or PID movement",
    "no eBPF: no eBPF program loading or attachment",
    "no PID movement: no processes moved between cgroups",
];

/// Render the design-gated rejection message for a blocked command.
pub(crate) fn render_design_gated_message(command_name: &str) -> String {
    let mut lines = Vec::with_capacity(DESIGN_GATED_DISCLAIMERS.len() + 2);
    lines.push(format!(
        "error: '{}' is design-gated and not yet available.",
        command_name
    ));
    lines.push(String::new());
    for d in DESIGN_GATED_DISCLAIMERS {
        lines.push(format!("  - {}", d));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod v31_gate_tests;
