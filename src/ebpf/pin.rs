// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pin path constants + cleanup helpers.
//! Single source of truth for all BPF pin file paths.

use std::path::PathBuf;

use anyhow::Result;
use aya::maps::{Array as BpfArray, MapData};

/// Root pin directory on bpffs.
pub const PIN_DIR: &str = "/sys/fs/bpf/zelynic";

/// Program pins (BPF programs stay loaded after process exit).
pub const PIN_PROG_DL: &str = "/sys/fs/bpf/zelynic/enforce_dl";
pub const PIN_PROG_UL: &str = "/sys/fs/bpf/zelynic/enforce_ul";

/// Link pins (bpf_links stay attached after process exit).
pub const PIN_LINK_DL: &str = "/sys/fs/bpf/zelynic/enforce_dl_link";
pub const PIN_LINK_UL: &str = "/sys/fs/bpf/zelynic/enforce_ul_link";

/// Map pins (all 8 maps are pinned via LIBBPF_PIN_BY_NAME).
pub const PIN_MAP_POLICY_DL: &str = "/sys/fs/bpf/zelynic/cgroup_policy_dl";
pub const PIN_MAP_POLICY_UL: &str = "/sys/fs/bpf/zelynic/cgroup_policy_ul";
pub const PIN_MAP_BUCKET_DL: &str = "/sys/fs/bpf/zelynic/cgroup_bucket_dl";
pub const PIN_MAP_BUCKET_UL: &str = "/sys/fs/bpf/zelynic/cgroup_bucket_ul";
pub const PIN_MAP_GROUP_BUCKET_DL: &str = "/sys/fs/bpf/zelynic/group_bucket_dl";
pub const PIN_MAP_GROUP_BUCKET_UL: &str = "/sys/fs/bpf/zelynic/group_bucket_ul";
pub const PIN_MAP_WATCHDOG: &str = "/sys/fs/bpf/zelynic/watchdog_deadline";
pub const PIN_MAP_STATS: &str = "/sys/fs/bpf/zelynic/cgroup_limiter_stats";
pub const PIN_MAP_SCHEMA_VERSION: &str = "/sys/fs/bpf/zelynic/schema_version";

/// Read the pinned schema version. Returns None if pin doesn't exist or read fails.
pub fn read_pinned_schema_version() -> Option<u32> {
    let map_data = MapData::from_pin(PIN_MAP_SCHEMA_VERSION).ok()?;
    let map_obj = aya::maps::Map::Array(map_data);
    let map: BpfArray<_, u32> = BpfArray::try_from(&map_obj).ok()?;
    let key: u32 = 0;
    map.get(&key, 0).ok()
}

/// Check if the pin directory has any files.
pub fn pin_dir_has_files() -> bool {
    let pin_dir = PathBuf::from(PIN_DIR);
    pin_dir.exists()
        && std::fs::read_dir(&pin_dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
}

/// Remove ALL pin files + directory. Full cleanup.
pub fn unpin_all() -> Result<()> {
    let pin_dir = PathBuf::from(PIN_DIR);
    if pin_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&pin_dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let _ = std::fs::remove_dir(&pin_dir);
    }
    Ok(())
}
