// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! File-based lock to prevent concurrent zelynic operations.
//!
//! ## Why this exists
//!
//! zelynic is fire-and-forget: `strict-single` loads BPF, writes policy,
//! and exits. If two operations run simultaneously (e.g., user runs
//! `strict-single brave 100kb` in one terminal and `unstrict-all` in
//! another), they can corrupt BPF state:
//!
//! 1. Terminal 1: `attach()` loads BPF + pins programs
//! 2. Terminal 2: `unpin_all()` removes all pins
//! 3. Terminal 1: `apply_single()` tries to write policy → map gone → ENOENT
//!
//! The lock prevents this: the second operation waits (or errors if
//! non-blocking) until the first completes.
//!
//! ## How it works
//!
//! Uses `flock(2)` on `/tmp/zelynic.lock`. The lock is automatically
//! released when the file descriptor is closed (on process exit, including
//! crash/panic/SIGKILL). This is simpler and more robust than PID files.

use anyhow::{bail, Result};
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

/// Lock file path. /tmp is always available and writable by root.
const LOCK_FILE: &str = "/tmp/zelynic.lock";

/// Acquire an exclusive lock on the zelynic lock file.
///
/// Returns a `File` guard. The lock is held as long as the guard is alive.
/// When dropped (on function return, process exit, panic, or SIGKILL),
/// the lock is automatically released.
///
/// Uses non-blocking `flock(LOCK_EX | LOCK_NB)`: if another operation is
/// in progress, returns an error immediately rather than waiting.
pub fn acquire() -> Result<std::fs::File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(LOCK_FILE)
        .map_err(|e| anyhow::anyhow!("Failed to open lock file {LOCK_FILE}: {e}"))?;

    // Non-blocking exclusive lock. If held by another process, return error.
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            bail!(
                "another zelynic operation is in progress. \
                 Wait for it to finish, then retry. \
                 If no operation is running, run 'zelynic recover'."
            );
        }
        bail!("Failed to acquire lock: {err}");
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_lock() {
        // Should be able to acquire lock (assuming no other test holds it).
        let lock = acquire();
        assert!(lock.is_ok(), "should acquire lock: {:?}", lock.err());

        // Second acquire should fail (lock is held by this process).
        let lock2 = acquire();
        assert!(lock2.is_err(), "second acquire should fail");

        // Drop the first lock.
        drop(lock);

        // Now should be able to acquire again.
        let lock3 = acquire();
        assert!(
            lock3.is_ok(),
            "should acquire after drop: {:?}",
            lock3.err()
        );
    }
}
