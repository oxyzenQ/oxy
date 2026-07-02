// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Identity mapping — resolve cgroup IDs to process names and users.
//!
//! Walks /proc and /sys/fs/cgroup to build a reverse map:
//! cgroup_id (u32) → ProcessIdentity.
//!
//! Refreshed periodically (default 10s TTL) to handle process churn without
//! paying the /proc walk cost on every observer poll.
//!
//! # Wolf Architecture — Layer 2: Identity Resolution
//!
//! BPF programs return raw cgroup IDs. To make output human-readable, we
//! reverse-resolve: walk /proc to find which PID lives in which cgroup, then
//! look up the cgroup's path and the process's name/uid.
//!
//! This layer is **userspace-only** and **best-effort**: if resolution fails,
//! we fall back to raw `cg:{id}` labels. The BPF program is unaffected.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// Default refresh interval: rebuild the identity map every 10 seconds.
const DEFAULT_REFRESH_TTL_SECS: u64 = 10;

/// Process identity information.
#[derive(Debug, Clone, Default)]
pub struct ProcessIdentity {
    pub cgroup_id: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub cgroup_path: Option<String>,
}

/// Cached identity mapping: cgroup_id (u32) → ProcessIdentity.
///
/// Refreshed periodically to handle process churn. Build cost is O(nproc),
/// paid once per TTL window.
#[derive(Debug)]
pub struct IdentityMap {
    cache: HashMap<u32, ProcessIdentity>,
    last_refresh: Option<Instant>,
    refresh_ttl: Duration,
}

impl Default for IdentityMap {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityMap {
    /// Create new empty identity map with default 10s refresh TTL.
    pub fn new() -> Self {
        IdentityMap {
            cache: HashMap::new(),
            last_refresh: None,
            refresh_ttl: Duration::from_secs(DEFAULT_REFRESH_TTL_SECS),
        }
    }

    /// Create with custom refresh TTL (useful for testing).
    pub fn with_ttl(ttl: Duration) -> Self {
        IdentityMap {
            cache: HashMap::new(),
            last_refresh: None,
            refresh_ttl: ttl,
        }
    }

    /// Force a full refresh: walk /proc to rebuild the reverse map.
    ///
    /// For each live PID:
    /// 1. Read `/proc/<pid>/cgroup` → cgroup path (v2 format: `0::/path`)
    /// 2. Read `/sys/fs/cgroup{path}/cgroup.id` → 64-bit cgroup ID
    /// 3. Truncate to u32 to match BPF map key
    /// 4. Read `/proc/<pid>/comm` → process name
    /// 5. Read `/proc/<pid>/status` → uid
    ///
    /// First PID wins per cgroup_id (multiple PIDs share a cgroup; we only
    /// need one representative for display purposes).
    ///
    /// Returns the number of unique cgroups discovered.
    pub fn refresh(&mut self) -> usize {
        self.cache.clear();

        let proc_entries = match fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => {
                self.last_refresh = Some(Instant::now());
                return 0;
            }
        };

        for entry in proc_entries.flatten() {
            let name = entry.file_name();
            let name_str = match name.to_str() {
                Some(s) => s,
                None => continue,
            };

            // Only numeric directories are PIDs.
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Read /proc/<pid>/cgroup.
            let cgroup_file = format!("/proc/{pid}/cgroup");
            let cgroup_content = match fs::read_to_string(&cgroup_file) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Parse "0::/path/to/cgroup" (cgroup v2 single-line format).
            // Lines like "0::/user.slice/..." — take the part after "::".
            let cgroup_path = cgroup_content
                .lines()
                .next()
                .and_then(|line| line.split("::").nth(1))
                .map(|s| s.trim().to_string());

            let cgroup_path = match cgroup_path {
                Some(p) if !p.is_empty() => p,
                _ => continue,
            };

            // Resolve cgroup_id via /sys/fs/cgroup{path}/cgroup.id (kernel 5.13+).
            let full_path = format!("/sys/fs/cgroup{cgroup_path}");
            let cgroup_id_64 = match cgroup_id_from_path(&full_path) {
                Some(id) => id,
                None => continue,
            };

            // Truncate to u32 to match BPF map key type.
            // On a single system, cgroup IDs are well under 2^32 in practice.
            let cgroup_id = cgroup_id_64 as u32;

            // Skip if we already have an entry for this cgroup.
            if self.cache.contains_key(&cgroup_id) {
                continue;
            }

            // Read /proc/<pid>/comm for the process name.
            let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            // Read /proc/<pid>/status for uid (first field after "Uid:").
            let uid = fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|u| u.parse().ok())
                })
                .unwrap_or(0);

            self.cache.insert(
                cgroup_id,
                ProcessIdentity {
                    cgroup_id,
                    pid,
                    uid,
                    comm,
                    cgroup_path: Some(cgroup_path),
                },
            );
        }

        self.last_refresh = Some(Instant::now());
        self.cache.len()
    }

    /// Refresh if the TTL has elapsed. Returns true if a refresh happened.
    pub fn maybe_refresh(&mut self) -> bool {
        let needs_refresh = match self.last_refresh {
            None => true,
            Some(last) => last.elapsed() >= self.refresh_ttl,
        };

        if needs_refresh {
            self.refresh();
            true
        } else {
            false
        }
    }

    /// Look up identity for a cgroup ID. Returns None if not in cache.
    pub fn get(&self, cgroup_id: u32) -> Option<&ProcessIdentity> {
        self.cache.get(&cgroup_id)
    }

    /// Get a short display label for a cgroup ID.
    ///
    /// Format: `cg:73386 (firefox)` if resolved, else `cg:73386`.
    pub fn label(&self, cgroup_id: u32) -> String {
        match self.get(cgroup_id) {
            Some(id) if !id.comm.is_empty() => {
                format!("cg:{cgroup_id} ({})", id.comm)
            }
            _ => format!("cg:{cgroup_id}"),
        }
    }

    /// Get a verbose display label including the cgroup path.
    ///
    /// Format: `cg:73386 (firefox) /user.slice/...` if resolved with path,
    /// `cg:73386 (firefox)` if resolved without path, else `cg:73386`.
    pub fn label_verbose(&self, cgroup_id: u32) -> String {
        match self.get(cgroup_id) {
            Some(id) if !id.comm.is_empty() && id.cgroup_path.is_some() => {
                format!(
                    "cg:{cgroup_id} ({}) {}",
                    id.comm,
                    id.cgroup_path.as_ref().unwrap()
                )
            }
            Some(id) if !id.comm.is_empty() => {
                format!("cg:{cgroup_id} ({})", id.comm)
            }
            _ => format!("cg:{cgroup_id}"),
        }
    }

    /// Clear cache and reset refresh timestamp.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.last_refresh = None;
    }

    /// Number of cached identities.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// All known identities (unspecified order).
    pub fn all(&self) -> Vec<&ProcessIdentity> {
        self.cache.values().collect()
    }
}

/// Resolve a 64-bit cgroup ID from a cgroup v2 path.
///
/// Strategy:
/// 1. Try `/sys/fs/cgroup{path}/cgroup.id` file (kernel 5.13+).
/// 2. Fall back to `stat()` inode number (works on older kernels, but the
///    inode is NOT guaranteed to equal the BPF cgroup ID — use with caution).
///
/// On the user's system (kernel 6.18), the cgroup.id file is authoritative.
fn cgroup_id_from_path(path: &str) -> Option<u64> {
    // Method 1: read cgroup.id file (authoritative for cgroup v2, kernel 5.13+).
    let id_file = Path::new(path).join("cgroup.id");
    if let Ok(id_str) = fs::read_to_string(&id_file) {
        if let Ok(id) = id_str.trim().parse::<u64>() {
            return Some(id);
        }
    }

    // Method 2: stat() fallback. For cgroup v2 on modern kernels, the inode
    // number IS the cgroup ID — but this is an implementation detail. Use
    // only when cgroup.id file is unavailable.
    if let Ok(meta) = fs::metadata(path) {
        return Some(meta.ino());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_identity_map_new_is_empty() {
        let map = IdentityMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_label_for_unknown_cgroup() {
        let map = IdentityMap::new();
        // No refresh — cache is empty.
        assert_eq!(map.label(99999), "cg:99999");
    }

    #[test]
    fn test_label_verbose_for_unknown_cgroup() {
        let map = IdentityMap::new();
        assert_eq!(map.label_verbose(99999), "cg:99999");
    }

    #[test]
    fn test_get_returns_none_when_empty() {
        let map = IdentityMap::new();
        assert!(map.get(1).is_none());
    }

    #[test]
    fn test_clear_resets_cache() {
        // Insert a fake entry by manually manipulating cache via refresh.
        // Since refresh() on /proc may or may not find entries in CI,
        // we test the clear() contract independently.
        let mut map = IdentityMap::new();
        // After clear on an empty map, should still be empty.
        map.clear();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_with_ttl_constructor() {
        let map = IdentityMap::with_ttl(Duration::from_millis(1));
        assert!(map.is_empty());
        assert_eq!(map.refresh_ttl, Duration::from_millis(1));
    }

    #[test]
    fn test_maybe_refresh_when_no_last_refresh() {
        // When last_refresh is None, maybe_refresh should trigger.
        // We can't easily test the actual refresh without /proc access,
        // but we can verify the contract: maybe_refresh returns true and
        // sets last_refresh.
        let mut map = IdentityMap::with_ttl(Duration::from_secs(60));
        let refreshed = map.maybe_refresh();
        assert!(refreshed);
        assert!(map.last_refresh.is_some());
    }

    #[test]
    fn test_maybe_refresh_skips_when_within_ttl() {
        let mut map = IdentityMap::with_ttl(Duration::from_secs(60));
        // Prime the cache.
        let _ = map.maybe_refresh();
        let first_refresh = map.last_refresh.unwrap();

        // Second call should NOT refresh (within TTL).
        let refreshed = map.maybe_refresh();
        assert!(!refreshed);
        assert_eq!(map.last_refresh.unwrap(), first_refresh);
    }

    #[test]
    fn test_label_with_manually_inserted_identity() {
        // Test the label() formatting directly by inserting a fake entry.
        let mut map = IdentityMap::new();
        map.cache.insert(
            12345,
            ProcessIdentity {
                cgroup_id: 12345,
                pid: 1000,
                uid: 1000,
                comm: "firefox".to_string(),
                cgroup_path: Some("/user.slice/user-1000.slice/...".to_string()),
            },
        );

        assert_eq!(map.label(12345), "cg:12345 (firefox)");
        assert_eq!(
            map.label_verbose(12345),
            "cg:12345 (firefox) /user.slice/user-1000.slice/..."
        );
    }

    #[test]
    fn test_label_with_empty_comm_falls_back() {
        let mut map = IdentityMap::new();
        map.cache.insert(
            12345,
            ProcessIdentity {
                cgroup_id: 12345,
                pid: 1000,
                uid: 1000,
                comm: String::new(),
                cgroup_path: None,
            },
        );

        // Empty comm → fall back to raw label.
        assert_eq!(map.label(12345), "cg:12345");
        assert_eq!(map.label_verbose(12345), "cg:12345");
    }

    #[test]
    fn test_refresh_runs_without_panic() {
        // Refresh should always succeed (even if /proc has 0 entries or
        // permissions block some reads). Must not panic.
        let mut map = IdentityMap::new();
        let _count = map.refresh();
        // last_refresh must be set after a refresh.
        assert!(map.last_refresh.is_some());
    }

    #[test]
    fn test_all_returns_cached_values() {
        let mut map = IdentityMap::new();
        map.cache.insert(
            1,
            ProcessIdentity {
                cgroup_id: 1,
                pid: 1,
                uid: 0,
                comm: "init".to_string(),
                cgroup_path: Some("/".to_string()),
            },
        );
        map.cache.insert(
            2,
            ProcessIdentity {
                cgroup_id: 2,
                pid: 100,
                uid: 1000,
                comm: "shell".to_string(),
                cgroup_path: Some("/user.slice".to_string()),
            },
        );

        let all = map.all();
        assert_eq!(all.len(), 2);
    }
}
