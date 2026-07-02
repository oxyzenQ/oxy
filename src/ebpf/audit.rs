// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Audit log — JSONL event log for eBPF enforcement actions.
//!
//! Wolf Architecture safety layer: records every policy apply, enforcement
//! start/stop, and watchdog event to `~/.local/share/zelynic/audit.jsonl`.
//!
//! Used for post-mortem debugging: "why was firefox slow at 3pm?" → grep
//! the audit log for policy_apply events on firefox's cgroup.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;
use serde_json::json;

/// JSONL audit log for eBPF enforcement events.
pub struct AuditLog {
    path: PathBuf,
}

/// Event types logged by the eBPF limiter.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// Enforcement started (BPF attached, watchdog set).
    EnforceStart { policy_count: usize },
    /// A policy was applied to a cgroup.
    PolicyApply {
        cgroup_id: u32,
        comm: String,
        rate_bps: u64,
        burst_bytes: u64,
    },
    /// Enforcement stopped (normal exit, duration reached, or Ctrl+C).
    EnforceStop { reason: String },
    /// Watchdog was refreshed (debug, logged at most once per 5s).
    WatchdogRefresh { remaining_secs: u64 },
    /// A rate was rejected by the min-rate guard.
    RateRejected {
        target: String,
        rate_bps: u64,
        reason: String,
    },
}

impl AuditLog {
    /// Create or open the audit log at `~/.local/share/zelynic/audit.jsonl`.
    /// Falls back to `/tmp/zelynic-audit.jsonl` if HOME is unset.
    pub fn open() -> Self {
        let path = audit_path();
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        AuditLog { path }
    }

    /// Log an event as a single JSON line.
    pub fn log(&self, event: &AuditEvent) {
        let (event_type, mut entry) = match event {
            AuditEvent::EnforceStart { policy_count } => {
                ("enforce_start", json!({ "policy_count": policy_count }))
            }
            AuditEvent::PolicyApply {
                cgroup_id,
                comm,
                rate_bps,
                burst_bytes,
            } => (
                "policy_apply",
                json!({
                    "cgroup_id": cgroup_id,
                    "comm": comm,
                    "rate_bps": rate_bps,
                    "burst_bytes": burst_bytes,
                }),
            ),
            AuditEvent::EnforceStop { reason } => ("enforce_stop", json!({ "reason": reason })),
            AuditEvent::WatchdogRefresh { remaining_secs } => (
                "watchdog_refresh",
                json!({ "remaining_secs": remaining_secs }),
            ),
            AuditEvent::RateRejected {
                target,
                rate_bps,
                reason,
            } => (
                "rate_rejected",
                json!({
                    "target": target,
                    "rate_bps": rate_bps,
                    "reason": reason,
                }),
            ),
        };

        entry["ts"] = json!(Utc::now().to_rfc3339());
        entry["event"] = json!(event_type);

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{entry}");
        }
    }

    /// Get the audit log file path (for display purposes).
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// Compute the audit log path.
fn audit_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share/zelynic/audit.jsonl")
    } else {
        PathBuf::from("/tmp/zelynic-audit.jsonl")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_audit_path_uses_xdg() {
        // With HOME set, path should be under ~/.local/share/zelynic/
        env::set_var("HOME", "/tmp/test-home-zelynic");
        let path = audit_path();
        assert!(path
            .to_string_lossy()
            .contains(".local/share/zelynic/audit.jsonl"));
    }

    #[test]
    fn test_audit_log_open_does_not_panic() {
        // open() should never panic, even if directory creation fails.
        let log = AuditLog::open();
        assert!(log.path().parent().is_some());
    }

    #[test]
    fn test_log_enforce_start() {
        let log = AuditLog::open();
        // Should not panic.
        log.log(&AuditEvent::EnforceStart { policy_count: 3 });
    }

    #[test]
    fn test_log_policy_apply() {
        let log = AuditLog::open();
        log.log(&AuditEvent::PolicyApply {
            cgroup_id: 73386,
            comm: "firefox".to_string(),
            rate_bps: 1_000_000,
            burst_bytes: 1_000_000,
        });
    }

    #[test]
    fn test_log_enforce_stop() {
        let log = AuditLog::open();
        log.log(&AuditEvent::EnforceStop {
            reason: "duration reached".to_string(),
        });
    }

    #[test]
    fn test_log_rate_rejected() {
        let log = AuditLog::open();
        log.log(&AuditEvent::RateRejected {
            target: "firefox".to_string(),
            rate_bps: 100,
            reason: "below minimum 1024 B/s".to_string(),
        });
    }
}
