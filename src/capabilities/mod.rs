// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Capability detection (Dragon Architecture — eBPF only).
//!
//! Simplified from the legacy tc/nft/systemd scoring matrix. Now only
//! detects: cgroup v2, BPF filesystem, kernel version, root privileges.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// System information relevant to eBPF support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub kernel: String,
    pub cgroup_v2: bool,
    pub cgroup2_mount_path: Option<String>,
    pub bpf_fs_mounted: bool,
    pub is_root: bool,
}

/// Capability detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub system: SystemInfo,
    pub ebpf_supported: bool,
    pub warnings: Vec<String>,
}

/// Detect system capabilities for eBPF.
pub fn detect() -> CapabilityReport {
    let system = detect_system();
    let ebpf_supported = system.cgroup_v2 && system.bpf_fs_mounted;

    let mut warnings = Vec::new();
    if !system.cgroup_v2 {
        warnings.push("cgroup v2 not detected. eBPF observer requires cgroup v2.".to_string());
    }
    if !system.bpf_fs_mounted {
        warnings.push("BPF filesystem not mounted at /sys/fs/bpf.".to_string());
    }
    if !system.is_root {
        warnings.push("Not running as root. eBPF operations require root.".to_string());
    }

    CapabilityReport {
        system,
        ebpf_supported,
        warnings,
    }
}

/// Detect basic system info.
fn detect_system() -> SystemInfo {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let cgroup2_mount_path = find_cgroup2_mount();
    let cgroup_v2 = cgroup2_mount_path.is_some();

    let bpf_fs_mounted = PathBuf::from("/sys/fs/bpf").exists();

    let is_root = nix::unistd::geteuid().is_root();

    SystemInfo {
        kernel,
        cgroup_v2,
        cgroup2_mount_path,
        bpf_fs_mounted,
        is_root,
    }
}

/// Find cgroup v2 mount point by parsing /proc/mounts.
fn find_cgroup2_mount() -> Option<String> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "cgroup2" {
            return Some(parts[1].to_string());
        }
    }
    None
}

/// Run capability detection and print report.
pub fn run_doctor(json: bool) -> Result<()> {
    let report = detect();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }
    Ok(())
}

fn print_report(report: &CapabilityReport) {
    use colored::Colorize;

    println!("{}", "━━━ zelynic eBPF Capability Doctor ━━━".bold());
    println!();
    println!("  Kernel:     {}", report.system.kernel);
    println!(
        "  cgroup v2:  {}",
        if report.system.cgroup_v2 {
            "YES".green().bold()
        } else {
            "NO".red().bold()
        }
    );
    println!(
        "  BPF fs:     {}",
        if report.system.bpf_fs_mounted {
            "YES".green().bold()
        } else {
            "NO".red().bold()
        }
    );
    println!(
        "  Root:       {}",
        if report.system.is_root {
            "YES".green().bold()
        } else {
            "NO".yellow().bold()
        }
    );
    println!(
        "  eBPF:       {}",
        if report.ebpf_supported {
            "SUPPORTED".green().bold()
        } else {
            "NOT SUPPORTED".red().bold()
        }
    );

    if !report.warnings.is_empty() {
        println!();
        println!("{}", "Warnings:".yellow().bold());
        for w in &report.warnings {
            println!("  ⚠ {w}");
        }
    }

    if report.ebpf_supported && report.system.is_root {
        println!();
        println!(
            "  {} Run `zelynic strict-single <target> <rate>` or `zelynic observe`",
            "Ready:".green().bold()
        );
    }
}

use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_does_not_panic() {
        // detect() should never panic, even in restricted environments.
        let report = detect();
        // We can't assert specific values (depends on environment), but
        // the report should be well-formed.
        assert!(!report.system.kernel.is_empty());
    }

    #[test]
    fn test_capability_report_serializes() {
        let report = CapabilityReport {
            system: SystemInfo {
                kernel: "6.18.0".to_string(),
                cgroup_v2: true,
                cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
                bpf_fs_mounted: true,
                is_root: false,
            },
            ebpf_supported: true,
            warnings: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("cgroup_v2"));
        assert!(json.contains("ebpf_supported"));
    }
}
