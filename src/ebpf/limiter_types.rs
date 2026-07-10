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

/// BPF schema version. Must match `SCHEMA_VERSION` in `bpf/limiter.bpf.c`.
/// Increment both when BPF struct layouts change. Userspace checks the pinned
/// schema_version map on attach — if mismatch, cleans up + reloads.
/// v1: initial (no frac_rem in bucket, no schema_version map)
/// v2: added frac_rem to bucket for fractional token tracking
pub const SCHEMA_VERSION_EXPECTED: u32 = 2;

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
    pub frac_rem: u64,
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

/// Format a byte count using decimal SI units (1 KB = 1000 bytes).
///
/// This is consistent with `parse_rate` which uses decimal units (1kb = 1000).
/// Network rates conventionally use SI units (1 Mbps = 1,000,000 bps).
///
/// Examples: 500 → "500 B", 1500 → "1.5 KB", 1_500_000 → "1.5 MB",
///           1_500_000_000 → "1.50 GB"
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1000 {
        format!("{bytes} B")
    } else if bytes < 1_000_000 {
        format!("{:.1} KB", bytes as f64 / 1000.0)
    } else if bytes < 1_000_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    }
}

/// Format a rate (bytes per second) with "/s" suffix.
/// Uses decimal SI units, consistent with `parse_rate` and `format_bytes`.
///
/// Examples: 100_000 → "100.0 KB/s", 1_000_000 → "1.0 MB/s"
pub fn format_rate(bps: u64) -> String {
    format!("{}/s", format_bytes(bps))
}

/// Get terminal width in columns. Uses ioctl TIOCGWINSZ.
/// Falls back to 80 if detection fails (piped output, no tty).
pub fn terminal_width() -> usize {
    use libc::{ioctl, winsize, STDOUT_FILENO, TIOCGWINSZ};
    let mut ws: winsize = winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: ioctl with TIOCGWINSZ writes to a valid winsize struct.
    let ret = unsafe { ioctl(STDOUT_FILENO, TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        80
    }
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

    // ━━ Precision tests ━━

    #[test]
    fn test_format_bytes_decimal_si() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1000), "1.0 KB");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(100_000), "100.0 KB");
        assert_eq!(format_bytes(999_999), "1000.0 KB");
        assert_eq!(format_bytes(1_000_000), "1.0 MB");
        assert_eq!(format_bytes(1_500_000), "1.5 MB");
        assert_eq!(format_bytes(1_000_000_000), "1.00 GB");
    }

    #[test]
    fn test_format_rate_with_suffix() {
        assert_eq!(format_rate(0), "0 B/s");
        assert_eq!(format_rate(100_000), "100.0 KB/s");
        assert_eq!(format_rate(1_000_000), "1.0 MB/s");
        assert_eq!(format_rate(1_000_000_000), "1.00 GB/s");
    }

    #[test]
    fn test_parse_rate_consistent_with_format() {
        // Round-trip: parse("100kb") → 100000 → format → "100.0 KB/s"
        let rate = parse_rate("100kb").unwrap();
        assert_eq!(rate, 100_000);
        assert_eq!(format_rate(rate), "100.0 KB/s");

        let rate = parse_rate("1mb").unwrap();
        assert_eq!(rate, 1_000_000);
        assert_eq!(format_rate(rate), "1.0 MB/s");
    }

    #[test]
    fn test_bucket_raw_has_frac_rem() {
        // Verify BucketRaw has 3 fields (24 bytes) for schema v2.
        // v1 was 16 bytes (tokens + last_refill_ns only).
        let b = BucketRaw {
            tokens: 1000,
            last_refill_ns: 12345,
            frac_rem: 999_999_999,
        };
        assert_eq!(b.tokens, 1000);
        assert_eq!(b.last_refill_ns, 12345);
        assert_eq!(b.frac_rem, 999_999_999);
        assert_eq!(
            std::mem::size_of::<BucketRaw>(),
            24,
            "BucketRaw must be 24 bytes (3 × u64) for schema v2"
        );
    }

    /// Simulate BPF fractional token tracking in Rust to verify precision.
    /// This mirrors the logic in enforce() in bpf/limiter.bpf.c.
    #[test]
    fn test_fractional_tracking_precision() {
        const NS_PER_SEC: u64 = 1_000_000_000;

        // Simulate: rate = 97,700 bps (97.7 KB/s), 1000 refills of 1ms each.
        let rate_bps: u64 = 97_700;
        let elapsed_ns: u64 = 1_000_000; // 1ms

        let mut tokens: u64 = 0;
        let mut frac_rem: u64 = 0;

        for _ in 0..1000 {
            let product = elapsed_ns * rate_bps;
            let mut refill_whole = product / NS_PER_SEC;
            let refill_frac = product % NS_PER_SEC;

            let mut new_frac = frac_rem + refill_frac;
            if new_frac >= NS_PER_SEC {
                refill_whole += 1;
                new_frac -= NS_PER_SEC;
            }
            frac_rem = new_frac;
            tokens += refill_whole;
        }

        // With fractional tracking, 1000 × 1ms = 1 second of tokens.
        // Expected: 97,700 bytes (exact rate × 1 second).
        // Without fractional tracking: 97,000 bytes (truncated).
        assert_eq!(
            tokens, 97_700,
            "fractional tracking should give exact rate over 1 second"
        );

        // Verify the error is zero (was 0.72% without fractional tracking).
        let error_pct = ((tokens as i64 - 97_700) as f64 / 97_700.0).abs() * 100.0;
        assert!(
            error_pct < 0.01,
            "error should be < 0.01%, got {error_pct}%"
        );
    }

    /// Verify that without fractional tracking, there IS truncation error.
    /// This test documents the problem that fractional tracking solves.
    #[test]
    fn test_truncation_error_without_fractional() {
        const NS_PER_SEC: u64 = 1_000_000_000;

        let rate_bps: u64 = 97_700;
        let elapsed_ns: u64 = 1_000_000;

        let mut tokens: u64 = 0;

        for _ in 0..1000 {
            // Old formula: integer division, no fractional tracking.
            let refill = (elapsed_ns * rate_bps) / NS_PER_SEC;
            tokens += refill;
        }

        // Without fractional tracking: 97,000 (truncated from 97,700).
        // This is a 0.72% error — the problem fractional tracking fixes.
        assert_eq!(tokens, 97_000);
        let error_pct = (97_700 - tokens) as f64 / 97_700.0 * 100.0;
        assert!(error_pct > 0.5, "truncation error should be > 0.5%");
    }

    #[test]
    fn test_schema_version_constant() {
        // Must match SCHEMA_VERSION in bpf/limiter.bpf.c.
        // When this changes, the BPF code must also change.
        assert_eq!(SCHEMA_VERSION_EXPECTED, 2);
    }
}
