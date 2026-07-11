// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Raw BPF syscall helpers for creating + pining bpf_links.
//!
//! ## Why this module exists
//!
//! Aya 0.13's `CgroupSkb::attach()` creates a `bpf_link` (fd-based) on
//! kernel 5.7+. When the `Ebpf` object is dropped, Aya's `Drop` impl
//! closes all link fds → links are detached → BPF never executes.
//!
//! Aya 0.13 does NOT expose a public API to pin `CgroupSkb` links. The
//! `CgroupSkbLinkInner` enum (`Fd` vs `ProgAttach`) is `pub(crate)`, so
//! from outside the crate you cannot extract the `FdLink` to call its
//! `pin()` method.
//!
//! ## Workaround
//!
//! We bypass Aya's `attach()` and do it ourselves via raw `bpf()`
//! syscalls:
//!
//! 1. `BPF_LINK_CREATE` — creates a link fd (kernel 5.7+)
//! 2. `BPF_OBJ_PIN` — pins the link fd to bpffs so it survives process exit
//!
//! The pin file keeps the link alive in kernel even after the fd is
//! closed and the process exits. Removing the pin file detaches the link.

use anyhow::{bail, Context, Result};
use std::os::fd::RawFd;

// ━━ BPF syscall constants (from linux/bpf.h) ━━

/// BPF syscall command numbers.
const BPF_LINK_CREATE: i32 = 28;
const BPF_OBJ_PIN: i32 = 6;

/// BPF attach types for cgroup_skb.
pub const BPF_CGROUP_INET_INGRESS: u32 = 0;
pub const BPF_CGROUP_INET_EGRESS: u32 = 1;

/// Check if the running kernel supports bpf_link (kernel >= 5.7).
/// bpf_link_create was added in kernel 5.7 (2020). Virtually all modern
/// systems have it, but we check for graceful degradation on older kernels.
pub fn kernel_supports_bpf_link() -> bool {
    let kv = nix::sys::utsname::uname().ok();
    if let Some(uname) = kv {
        let release = uname.release().to_string_lossy();
        // Parse "5.7.0-arch1" or "5.15.0-generic" etc.
        let parts: Vec<&str> = release.split('.').collect();
        if parts.len() >= 2 {
            let major: u32 = parts[0].parse().unwrap_or(0);
            let minor: u32 = parts[1].parse().unwrap_or(0);
            return major > 5 || (major == 5 && minor >= 7);
        }
    }
    // If we can't detect, assume yes (most systems are 5.7+)
    true
}

// ━━ Attribute structs (must match kernel union bpf_attr layout) ━━

/// Attribute struct for `BPF_LINK_CREATE`.
///
/// Layout matches the first 16 bytes of `union bpf_attr` →
/// `struct { prog_fd, target_fd, attach_type, flags }`.
/// The kernel uses the `attr_size` parameter to determine which fields
/// are present; we pass only 56 bytes (16 bytes of fields + 40 bytes
/// of zero padding) which is sufficient for cgroup_skb attach.
#[repr(C)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
    _pad: [u8; 40],
}

impl Default for LinkCreateAttr {
    fn default() -> Self {
        Self {
            prog_fd: 0,
            target_fd: 0,
            attach_type: 0,
            flags: 0,
            _pad: [0u8; 40],
        }
    }
}

/// Attribute struct for `BPF_OBJ_PIN`.
#[repr(C)]
#[derive(Default)]
struct ObjPinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

// ━━ Syscall wrappers ━━

/// Create a `bpf_link` attaching `prog_fd` to `target_fd` (cgroup fd).
///
/// Returns the raw link fd on success. Caller owns the fd and must
/// close it (or pin it then close it).
///
/// Requires kernel 5.7+ (bpf_link_create was added in 5.7).
pub fn sys_bpf_link_create(prog_fd: RawFd, target_fd: RawFd, attach_type: u32) -> Result<RawFd> {
    let attr = LinkCreateAttr {
        prog_fd: prog_fd as u32,
        target_fd: target_fd as u32,
        attach_type,
        flags: 0,
        ..Default::default()
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_LINK_CREATE,
            &attr as *const _,
            std::mem::size_of::<LinkCreateAttr>(),
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        bail!(
            "BPF_LINK_CREATE failed: {err} (attach_type={attach_type}). \
             Requires kernel 5.7+ for bpf_link support."
        );
    }
    Ok(ret as RawFd)
}

/// Pin a BPF object (link or program) fd to a path on bpffs.
///
/// The parent directory must exist and be on a BPF filesystem (`bpffs`,
/// typically mounted at `/sys/fs/bpf`).
pub fn sys_bpf_obj_pin(fd: RawFd, path: &str) -> Result<()> {
    use std::ffi::CString;
    let path_c = CString::new(path).with_context(|| format!("Invalid pin path: {path}"))?;
    let attr = ObjPinAttr {
        pathname: path_c.as_ptr() as u64,
        bpf_fd: fd as u32,
        file_flags: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_PIN,
            &attr as *const _,
            std::mem::size_of::<ObjPinAttr>(),
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        bail!("BPF_OBJ_PIN failed for {path}: {err}");
    }
    Ok(())
}

/// Create a `bpf_link`, pin it to bpffs, and close the fd.
///
/// The link stays attached as long as the pin file exists. Removing
/// the pin file (e.g. via `unlink`) detaches the link in kernel.
///
/// # Arguments
/// * `prog_fd` - File descriptor of the loaded BPF program
/// * `cgroup_fd` - File descriptor of the target cgroup directory
/// * `attach_type` - `BPF_CGROUP_INET_INGRESS` or `BPF_CGROUP_INET_EGRESS`
/// * `link_pin_path` - Path on bpffs where the link will be pinned
pub fn create_and_pin_link(
    prog_fd: RawFd,
    cgroup_fd: RawFd,
    attach_type: u32,
    link_pin_path: &str,
) -> Result<()> {
    // Remove stale pin file if it exists (from a previous crashed run).
    let _ = std::fs::remove_file(link_pin_path);

    let link_fd = sys_bpf_link_create(prog_fd, cgroup_fd, attach_type)?;
    sys_bpf_obj_pin(link_fd, link_pin_path)?;
    // Close the link fd — the pin keeps the link alive in kernel.
    unsafe { libc::close(link_fd) };
    Ok(())
}
