// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
/// eBPF backend for zelynic bandwidth management.
///
/// This module provides an optional eBPF-based backend using aya-rs (Pure Rust eBPF).
/// When enabled with the `ebpf` feature flag, it can replace the tc/cgroup backend
/// for lower overhead and true per-process ingress limiting.
///
/// The eBPF backend is automatically selected at runtime if:
/// 1. The `ebpf` feature is compiled in
/// 2. The kernel supports eBPF (Linux 5.2+ for basic, 5.8+ for BPF LSM)
/// 3. The user has CAP_BPF capability (or root)
///
use colored::Colorize;
use std::fs;
use std::path::Path;

/// Kernel version information for capability detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    /// Parse kernel version from uname or /proc/version.
    pub fn current() -> Option<Self> {
        // Try /proc/version_signature first (Ubuntu-specific)
        if let Ok(sig) = fs::read_to_string("/proc/version_signature") {
            if let Some(v) = parse_version_signature(&sig) {
                return Some(v);
            }
        }

        // Try /proc/sys/kernel/osrelease
        if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            if let Some(v) = parse_version_string(&release) {
                return Some(v);
            }
        }

        // Fallback: uname -r via nix
        if let Ok(utsname) = nix::sys::utsname::uname() {
            if let Some(v) = parse_version_string(&utsname.release().to_string_lossy()) {
                return Some(v);
            }
        }

        None
    }

    /// Check if kernel meets minimum version requirement.
    pub fn meets_requirement(&self, major: u32, minor: u32, patch: u32) -> bool {
        if self.major > major {
            return true;
        }
        if self.major < major {
            return false;
        }
        // major == required.major
        if self.minor > minor {
            return true;
        }
        if self.minor < minor {
            return false;
        }
        // minor == required.minor
        self.patch >= patch
    }

    /// Format as human-readable string.
    pub fn format(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parse version from Ubuntu's version_signature file.
fn parse_version_signature(sig: &str) -> Option<KernelVersion> {
    // Format: "Ubuntu 5.15.0-105.115-generic 5.15.153"
    let parts: Vec<&str> = sig.split_whitespace().collect();
    if parts.len() >= 3 {
        parse_version_string(parts[2])
    } else {
        None
    }
}

/// Parse version from standard Linux version string.
fn parse_version_string(version: &str) -> Option<KernelVersion> {
    // Format: "5.15.0-105-generic" or "6.1.0-1-amd64"
    let main_part = version.split('-').next()?;
    let nums: Vec<&str> = main_part.split('.').collect();

    if nums.len() >= 2 {
        let major = nums[0].parse().ok()?;
        let minor = nums[1].parse().ok()?;
        let patch = nums.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some(KernelVersion {
            major,
            minor,
            patch,
        })
    } else {
        None
    }
}

/// Check if the system supports eBPF for bandwidth management.
pub fn check_ebpf_support() -> EbpfSupport {
    let kernel = KernelVersion::current();
    let kernel_str = kernel
        .map(|k| k.format())
        .unwrap_or_else(|| "unknown".to_string());

    // Check kernel version (5.2+ required for basic eBPF, 5.8+ for cgroup_skb)
    let kernel_ok = kernel
        .map(|k| k.meets_requirement(5, 2, 0))
        .unwrap_or(false);

    // Check for CAP_BPF capability or root
    let caps_ok = has_cap_bpf() || nix::unistd::geteuid().is_root();

    // Check /sys/fs/bpf is mounted
    let bpf_fs_ok = Path::new("/sys/fs/bpf").exists();

    // Check for required kernel configs
    let config_ok = check_kernel_configs();

    let supported = kernel_ok && caps_ok && bpf_fs_ok && config_ok;

    EbpfSupport {
        supported,
        kernel_version: kernel_str,
        kernel_ok,
        caps_ok,
        bpf_fs_ok,
        config_ok,
    }
}

/// Result of eBPF support check.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EbpfSupport {
    pub supported: bool,
    pub kernel_version: String,
    pub kernel_ok: bool,
    pub caps_ok: bool,
    pub bpf_fs_ok: bool,
    pub config_ok: bool,
}

impl EbpfSupport {
    /// Print support status to console.
    #[allow(dead_code)]
    pub fn print_status(&self) {
        let is_root = nix::unistd::geteuid().is_root();

        println!("{}", "eBPF Support Check".green().bold());
        println!("  Kernel version: {}", self.kernel_version.dimmed());
        println!(
            "  Kernel 5.2+: {}",
            if self.kernel_ok {
                "✓".green()
            } else {
                "✗".red()
            }
        );

        // Show CAP_BPF with context about why it failed
        if self.caps_ok {
            println!("  CAP_BPF/root: {}", "✓".green());
        } else if !is_root && self.kernel_ok && self.config_ok {
            println!("  CAP_BPF/root: {} (run with sudo to check)", "?".yellow());
        } else {
            println!("  CAP_BPF/root: {}", "✗".red());
        }

        println!(
            "  BPF fs mounted: {}",
            if self.bpf_fs_ok {
                "✓".green()
            } else {
                "✗".red()
            }
        );
        println!(
            "  Kernel configs: {}",
            if self.config_ok {
                "✓".green()
            } else {
                "✗".red()
            }
        );
        println!();

        // Overall status with context — note that eBPF is not yet implemented
        if self.supported {
            println!("  Overall: {}", "SUPPORTED".green().bold());
            println!(
                "  {} eBPF limiter is not yet implemented — zelynic uses tc/cgroup",
                "  ".dimmed()
            );
        } else if !is_root && self.kernel_ok && self.bpf_fs_ok && self.config_ok {
            println!("  Overall: {}", "LIKELY SUPPORTED".yellow().bold());
            println!("  {} Run with sudo to verify", "  ".dimmed());
        } else {
            println!("  Overall: {}", "NOT SUPPORTED".red().bold());
            println!(
                "  {} zelynic will continue using tc/cgroup backend (no impact)",
                "  ".dimmed()
            );
        }
    }
}

/// Check if process has CAP_BPF capability.
fn has_cap_bpf() -> bool {
    // Try to read effective capabilities from /proc/self/status
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                // Parse hex capabilities
                let hex = line.split_whitespace().nth(1).unwrap_or("0");
                if let Ok(caps) = u64::from_str_radix(hex, 16) {
                    // CAP_BPF is capability 39 (1 << 39)
                    return (caps & (1 << 39)) != 0;
                }
            }
        }
    }
    false
}

/// Check required kernel configuration.
fn check_kernel_configs() -> bool {
    let config_path = "/boot/config-";
    let uname = nix::sys::utsname::uname().ok();
    let release = uname.as_ref().map(|u| u.release().to_string_lossy());

    // Try to find config file
    let config_file = release
        .as_ref()
        .map(|r| format!("{}{}", config_path, r))
        .filter(|p| Path::new(p).exists())
        .or_else(|| {
            // Try /proc/config.gz
            if Path::new("/proc/config.gz").exists() {
                Some("/proc/config.gz".to_string())
            } else {
                None
            }
        });

    if let Some(path) = config_file {
        if path.ends_with(".gz") {
            // Check compressed config
            if let Ok(output) = std::process::Command::new("zcat").arg(&path).output() {
                let config = String::from_utf8_lossy(&output.stdout);
                return config_contains_ebpf(&config);
            }
        } else {
            // Check plain config
            if let Ok(config) = fs::read_to_string(&path) {
                return config_contains_ebpf(&config);
            }
        }
    }

    // Assume OK if we can't check
    true
}

/// Check if kernel config has eBPF support enabled.
fn config_contains_ebpf(config: &str) -> bool {
    let required = ["CONFIG_BPF=y", "CONFIG_BPF_SYSCALL=y", "CONFIG_BPF_JIT=y"];

    for option in &required {
        if !config.contains(option) {
            return false;
        }
    }

    true
}

/// Backend selection — reserved for future eBPF implementation.
/// Currently unused; zelynic always uses tc/cgroup.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// eBPF backend (lowest overhead, true per-process ingress)
    Ebpf,
    /// tc/cgroup backend (fallback, works everywhere)
    TcCgroup,
}

#[allow(dead_code)]
impl Backend {
    /// Auto-select backend based on system capabilities.
    pub fn auto_select() -> Self {
        let support = check_ebpf_support();

        if support.supported {
            Backend::Ebpf
        } else {
            Backend::TcCgroup
        }
    }

    /// Get backend name.
    pub fn name(&self) -> &'static str {
        match self {
            Backend::Ebpf => "eBPF",
            Backend::TcCgroup => "tc/cgroup",
        }
    }
}

/// Print current backend info.
#[allow(dead_code)]
pub fn print_backend_info() {
    let ebpf_support = check_ebpf_support();

    // eBPF limiter is not yet implemented — always report tc/cgroup as active
    println!("{} Using {} backend", "→".cyan(), "tc/cgroup".cyan().bold());
    println!(
        "  {} Active backend: nftables + HTB | cgroup v2",
        "ℹ".dimmed()
    );

    if ebpf_support.supported {
        println!(
            "  {} eBPF: supported on this system (not yet implemented)",
            "✓".green()
        );
    } else if !nix::unistd::geteuid().is_root()
        && ebpf_support.kernel_ok
        && ebpf_support.bpf_fs_ok
        && ebpf_support.config_ok
    {
        println!(
            "  {} eBPF: likely supported (run with sudo to verify)",
            "?".yellow()
        );
    }
}
