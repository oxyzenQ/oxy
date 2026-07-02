// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Integration tests for zelynic
//!
//! These tests require root privileges and a Linux system.
//! Run with: sudo cargo test --test integration_test

use std::process::Command;
use std::thread;
use std::time::Duration;

/// Test helper to run zelynic commands
///
/// Uses the release binary if available, otherwise falls back to debug.
fn zelynic_cmd() -> Command {
    let binary = env!("CARGO_BIN_EXE_zelynic");
    let mut cmd = Command::new(binary);
    cmd.env("NO_COLOR", "1");
    cmd
}

/// Test that zelynic list works
#[test]
#[ignore = "requires root"]
fn test_list_basic() {
    let output = zelynic_cmd()
        .arg("list")
        .output()
        .expect("Failed to execute zelynic list");

    assert!(
        output.status.success(),
        "zelynic list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "zelynic list produced no output");
}

/// Test JSON output format
#[test]
#[ignore = "requires root"]
fn test_list_json() {
    let output = zelynic_cmd()
        .arg("list")
        .arg("--json")
        .output()
        .expect("Failed to execute zelynic list --json");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify valid JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "JSON output is not valid: {}", stdout);
}

/// Test bandwidth rate parsing via command
#[test]
#[ignore = "requires root"]
fn test_rate_parse() {
    // Test that invalid rate produces error
    let output = zelynic_cmd()
        .args(["strict", "-d", "invalid", "12345"])
        .output()
        .expect("Failed to execute zelynic strict");

    assert!(!output.status.success(), "Invalid rate should fail");
}

/// Test strict -> unstrict cycle
#[test]
#[ignore = "requires root and sleep process"]
#[allow(clippy::zombie_processes)]
fn test_strict_unstrict_cycle() {
    // Start a sleep process
    let mut sleep_cmd = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("Failed to start sleep process");

    let pid = sleep_cmd.id();

    // Give process time to start
    thread::sleep(Duration::from_millis(100));

    // Apply limit
    let output = zelynic_cmd()
        .args(["strict", "-d", "1mb", &pid.to_string()])
        .output()
        .expect("Failed to apply limit");

    assert!(
        output.status.success(),
        "Failed to apply limit: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check status
    let output = zelynic_cmd()
        .arg("status")
        .output()
        .expect("Failed to get status");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&pid.to_string()),
        "Status should show limited process"
    );

    // Remove limit
    let output = zelynic_cmd()
        .args(["unstrict", &pid.to_string()])
        .output()
        .expect("Failed to remove limit");

    assert!(
        output.status.success(),
        "Failed to remove limit: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Cleanup
    let _ = sleep_cmd.kill();
}

/// Test profile save and apply
#[test]
#[ignore = "requires root"]
fn test_profile_save_apply() {
    // Save a test profile
    let output = zelynic_cmd()
        .args(["profile", "save", "test-profile", "-d", "5mb", "-u", "2mb"])
        .output()
        .expect("Failed to save profile");

    assert!(
        output.status.success(),
        "Failed to save profile: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List profiles
    let output = zelynic_cmd()
        .args(["profile", "list"])
        .output()
        .expect("Failed to list profiles");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test-profile"),
        "Profile list should contain test-profile"
    );

    // Cleanup: delete test profile
    let _ = zelynic_cmd()
        .args(["profile", "delete", "test-profile"])
        .output();
}

/// Test completions generation
#[test]
fn test_completions_generation() {
    let shells = vec!["bash", "zsh", "fish", "powershell", "elvish"];

    for shell in shells {
        let output = zelynic_cmd()
            .args(["completions", shell])
            .output()
            .unwrap_or_else(|_| panic!("Failed to generate {} completions", shell));

        assert!(
            output.status.success(),
            "Failed to generate {} completions",
            shell
        );
        assert!(!output.stdout.is_empty(), "{} completions are empty", shell);
    }
}

/// Test man page generation
#[test]
fn test_man_generation() {
    let output = zelynic_cmd()
        .arg("man")
        .output()
        .expect("Failed to generate man page");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".TH"),
        "Man page should contain roff header"
    );
    assert!(
        stdout.contains("zelynic"),
        "Man page should contain 'zelynic'"
    );
}

/// Test backend info
#[test]
fn test_backend_info() {
    let output = zelynic_cmd()
        .arg("backend")
        .output()
        .expect("Failed to get backend info");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("backend") || stdout.contains("eBPF"),
        "Backend info should contain 'backend' or 'eBPF', got: {stdout}"
    );
}

/// Test version output
#[test]
fn test_version() {
    let output = zelynic_cmd()
        .arg("--version")
        .output()
        .expect("Failed to get version");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Version:")
            && stdout.contains("Source: https://github.com/oxyzenQ/zelynic"),
        "Version should contain complete zelynic metadata"
    );
}
