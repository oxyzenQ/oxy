// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Limiter types, constants, and helper functions.
//! Extracted from limiter.rs to keep file under 1000 LOC.

use anyhow::{bail, Result};
use std::path::PathBuf;

// ━━ Constants ━━

pub const BPF_OBJECT_PATH: &str = "bpf/limiter.bpf.o";

/// Minimum allowed rate: 1 KB/s.
pub const MIN_RATE: u64 = 1024;

/// Maximum allowed rate: 1 GB/s.
pub const MAX_RATE: u64 = 1_000_000_000;

// ━━ BPF map value structs (must match C structs) ━━

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct PolicyRaw {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub group_id: u32,
}

unsafe impl aya::Pod for PolicyRaw {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct BucketRaw {
    pub tokens: u64,
    pub last_refill_ns: u64,
}

unsafe impl aya::Pod for BucketRaw {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct LimiterStatsRaw {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub bytes_allowed: u64,
    pub bytes_dropped: u64,
}

unsafe impl aya::Pod for LimiterStatsRaw {}

// ━━ High-level API types ━━

#[derive(Debug, Clone)]
pub struct RateSpec {
    pub download: Option<u64>,
    pub upload: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum Target {
    CgroupId(u32),
    ProcessName(String),
}

impl Target {
    pub fn parse(s: &str) -> Self {
        if let Ok(id) = s.parse::<u32>() {
            Target::CgroupId(id)
        } else {
            Target::ProcessName(s.to_string())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    pub fn suffix(&self) -> &'static str {
        match self {
            Direction::Download => "dl",
            Direction::Upload => "ul",
        }
    }
}

// ━━ Free functions ━━

pub fn find_bpf_object() -> Result<PathBuf> {
    let candidates = [
        PathBuf::from(BPF_OBJECT_PATH),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BPF_OBJECT_PATH),
        PathBuf::from("/usr/lib/zelynic/limiter.bpf.o"),
        PathBuf::from("/usr/local/lib/zelynic/limiter.bpf.o"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    bail!(
        "BPF object file not found. Compile with:\n  \
         clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o\n  \
         Searched: {:?}",
        candidates
    )
}

/// Parse a rate string. Lowercase units only: kb, mb, gb, b.
pub fn parse_rate(s: &str) -> Result<u64> {
    let s = s.trim();

    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    let (num_part, multiplier) = if let Some(v) = s.strip_suffix("gb") {
        (v, 1_000_000_000u64)
    } else if let Some(v) = s.strip_suffix("mb") {
        (v, 1_000_000u64)
    } else if let Some(v) = s.strip_suffix("kb") {
        (v, 1_000u64)
    } else if let Some(v) = s.strip_suffix("b") {
        (v, 1u64)
    } else {
        bail!(
            "Invalid rate '{}'. Use lowercase: 1mb, 500kb, 1gb, or plain number",
            s
        );
    };

    let n: u64 = num_part
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid number in rate '{}': {}", s, e))?;

    Ok(n.saturating_mul(multiplier))
}

/// Validate rate is within bounds.
pub fn validate_rate(rate_bps: u64) -> Result<()> {
    if rate_bps < MIN_RATE {
        bail!(
            "Rate {} is below minimum ({} B/s = 1 KB/s).\n\
             Use --allow-dangerous to override.",
            rate_bps,
            MIN_RATE
        );
    }
    if rate_bps > MAX_RATE {
        bail!(
            "Rate {} is above maximum ({} B/s = 1 GB/s).",
            rate_bps,
            MAX_RATE
        );
    }
    Ok(())
}

/// Compute burst size: 1 second of traffic, clamped 4KB–100MB.
pub fn default_burst(rate_bps: u64) -> u64 {
    rate_bps.clamp(4096, 100_000_000)
}

/// Get monotonic time in nanoseconds (CLOCK_MONOTONIC).
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return 0;
        }
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn format_rate(bps: u64) -> String {
    format_bytes(bps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rate_plain_number() {
        assert_eq!(parse_rate("1000000").unwrap(), 1_000_000);
    }

    #[test]
    fn test_parse_rate_kb() {
        assert_eq!(parse_rate("1kb").unwrap(), 1_000);
        assert_eq!(parse_rate("500kb").unwrap(), 500_000);
    }

    #[test]
    fn test_parse_rate_mb() {
        assert_eq!(parse_rate("1mb").unwrap(), 1_000_000);
        assert_eq!(parse_rate("5mb").unwrap(), 5_000_000);
    }

    #[test]
    fn test_parse_rate_gb() {
        assert_eq!(parse_rate("1gb").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_rate_bytes() {
        assert_eq!(parse_rate("500b").unwrap(), 500);
    }

    #[test]
    fn test_parse_rate_rejects_uppercase() {
        assert!(parse_rate("1KB").is_err());
        assert!(parse_rate("1MB/s").is_err());
        assert!(parse_rate("1GB").is_err());
    }

    #[test]
    fn test_parse_rate_invalid() {
        assert!(parse_rate("abc").is_err());
        assert!(parse_rate("1xb").is_err());
        assert!(parse_rate("").is_err());
    }

    #[test]
    fn test_validate_rate_minimum() {
        assert!(validate_rate(512).is_err());
        assert!(validate_rate(1024).is_ok());
    }

    #[test]
    fn test_validate_rate_maximum() {
        assert!(validate_rate(2_000_000_000).is_err());
        assert!(validate_rate(1_000_000_000).is_ok());
    }

    #[test]
    fn test_default_burst_normal() {
        assert_eq!(default_burst(1_000_000), 1_000_000);
    }

    #[test]
    fn test_default_burst_minimum() {
        assert_eq!(default_burst(100), 4096);
    }

    #[test]
    fn test_default_burst_maximum() {
        assert_eq!(default_burst(1_000_000_000_000), 100_000_000);
    }

    #[test]
    fn test_target_parse_numeric() {
        match Target::parse("73386") {
            Target::CgroupId(id) => assert_eq!(id, 73386),
            _ => panic!("expected CgroupId"),
        }
    }

    #[test]
    fn test_target_parse_name() {
        match Target::parse("firefox") {
            Target::ProcessName(name) => assert_eq!(name, "firefox"),
            _ => panic!("expected ProcessName"),
        }
    }

    #[test]
    fn test_direction_suffix() {
        assert_eq!(Direction::Download.suffix(), "dl");
        assert_eq!(Direction::Upload.suffix(), "ul");
    }
}
