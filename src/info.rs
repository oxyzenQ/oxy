// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
/// zelynic package information constants and display functions.
///
/// Build metadata is embedded at compile time using env! macros.
/// For custom builds, set these via cargo build flags or build.rs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
#[allow(dead_code)]
pub const NAME: &str = "zelynic";
pub fn build_target() -> &'static str {
    // Dynamic build target label: detects arch + libc env at compile time.
    // Returns e.g. "amd64-gnu" (glibc, dynamic) or "amd64-musl" (static)
    // for x86_64 Linux builds. Other arches pass through with env suffix.
    if cfg!(target_env = "musl") {
        if cfg!(target_arch = "x86_64") {
            "amd64-musl"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-musl"
        } else {
            std::env::consts::ARCH
        }
    } else if cfg!(target_env = "gnu") {
        if cfg!(target_arch = "x86_64") {
            "amd64-gnu"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-gnu"
        } else {
            std::env::consts::ARCH
        }
    } else {
        match std::env::consts::ARCH {
            "x86_64" => "amd64",
            other => other,
        }
    }
}
pub const COPYRIGHT: &str = "(c) 2026 rezky_nightky (oxyzenQ)";
pub const LICENSE: &str = "GPL-3.0";
pub const REPOSITORY: &str = "https://github.com/oxyzenQ/zelynic";
#[allow(dead_code)]
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// Get the full version string.
fn version_string() -> String {
    format!("v{}", VERSION)
}

/// Get the build target string (architecture + OS).
fn build_string() -> String {
    format!("{}-{}", std::env::consts::OS, build_target())
}

/// Get the git commit hash injected at build time by build.rs.
fn build_hash() -> &'static str {
    option_env!("GIT_HASH").unwrap_or("unknown")
}

/// Print the package version in a compact format.
///
/// Output: `zelynic v2.0.0`
#[allow(dead_code)]
pub fn print_version() {
    println!("{} {}", NAME, version_string());
}

/// Print detailed package information.
///
/// ```text
/// Version: v2.0.0
/// Build: linux-amd64 (ad36a81)
/// Copyright: (c) 2026 rezky_nightky (oxyzenQ)
/// License: GPL-3.0
/// Source: https://github.com/oxyzenQ/zelynic
/// ```
pub fn print_info() {
    println!("Version: {}", version_string());
    println!("Build: {} ({})", build_string(), build_hash());
    println!("Architecture: Dragon (pure eBPF)");
    println!("Copyright: {}", COPYRIGHT);
    println!("License: {}", LICENSE);
    println!("Source: {}", REPOSITORY);
}
