// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF observer + limiter engine — real kernel-level traffic observation and enforcement.

// When ebpf feature is off, the modules are compiled out but ebpf_legacy
// re-exports + colored import may produce dead_code warnings. Suppress them.
#![allow(dead_code, unused_imports)]

#[cfg(feature = "ebpf")]
pub mod audit;
#[cfg(feature = "ebpf")]
pub mod identity;
#[cfg(feature = "ebpf")]
pub mod limiter;
#[cfg(feature = "ebpf")]
pub mod limiter_types;
#[cfg(feature = "ebpf")]
pub mod loader;

// Re-export capability detection (always available)
pub use crate::ebpf_legacy::*;

use colored::Colorize;

/// Print eBPF observer status.
#[cfg(feature = "ebpf")]
pub fn print_observer_status() {
    let support = check_ebpf_support();
    support.print_status();

    if support.supported {
        println!("  Observer: {}", "READY".green().bold());
        println!("  Usage: sudo zelynic ebpf observe");
    } else {
        println!("  Observer: {}", "NOT AVAILABLE".red().bold());
        println!("  Install: clang, libbpf-dev, then rebuild with --features ebpf");
    }
}

#[cfg(not(feature = "ebpf"))]
pub fn print_observer_status() {
    println!("  eBPF: not compiled (rebuild with --features ebpf)");
}
