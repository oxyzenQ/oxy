# Kernel Compatibility

> Requirements for running zelynic v5.0.0 (Dragon Architecture).

## Minimum Requirements

| Component | Minimum | Recommended | Why |
|-----------|---------|-------------|-----|
| **Kernel** | 5.13+ | 6.6 LTS+ | `cgroup.id` file (5.13+), `bpf_skb_cgroup_id()` (4.18+), `bpf_link` (5.7+) |
| **cgroup** | v2 only | v2 only | zelynic uses `cgroup_skb/egress` + `ingress` hooks |
| **BPF fs** | Mounted at `/sys/fs/bpf` | Mounted | Required for map + link pinning (fire-and-forget mode) |
| **Root** | Required | Required | BPF program load + attach requires `CAP_BPF` or root |
| **clang** | 10+ | 16+ | Compile BPF C programs to BPF bytecode |
| **libbpf-dev** | Any | Latest | BPF headers (`bpf_helpers.h`, `bpf_endian.h`) |

## Kernel Feature Dependencies

### `bpf_skb_cgroup_id(skb)` — kernel 4.18+
Returns the cgroup ID of the **socket owner** (not current task). This is critical
for correct attribution — TCP packets are processed in softirq context, not the
originating process. Available since kernel 4.18 (2018).

### `cgroup.id` file — kernel 5.13+
File at `/sys/fs/cgroup{path}/cgroup.id` containing the 64-bit cgroup ID.
Used by `IdentityMap` to resolve cgroup paths to IDs for display purposes.
On older kernels, falls back to `stat()` inode (less reliable).

### `bpf_link_create` + `BPF_OBJ_PIN` — kernel 5.7+
zelynic v4.9+ uses `bpf_link` (fd-based attachment) instead of legacy
`bpf_prog_attach`. Links are pinned to bpffs so enforcement survives
process exit. Aya 0.13's public API does not expose link pinning for
`CgroupSkb`, so zelynic uses raw `bpf()` syscalls. Requires kernel 5.7+
for `bpf_link_create`.

### `BPF_MAP_TYPE_ARRAY` + `BPF_MAP_TYPE_HASH` — kernel 4.18+
Standard BPF map types. Used for:
- `watchdog_deadline` (ARRAY, 1 entry)
- `cgroup_policy_dl/ul` (HASH, 1024 entries)
- `cgroup_bucket_dl/ul` (HASH, 1024 entries)
- `group_bucket_dl/ul` (HASH, 256 entries)
- `cgroup_limiter_stats` (HASH, 1024 entries)

### cgroup v2 — kernel 4.5+ (practical: 5.0+)
zelynic requires cgroup v2 (unified hierarchy). cgroup v1 is NOT supported.

Check: `stat -fc %T /sys/fs/cgroup` should return `cgroup2fs`.

## Distro Compatibility (v5.0.0)

| Distro | Kernel | Status | Notes |
|--------|--------|--------|-------|
| **Arch Linux** | 6.18+ | ✅ Verified | Dev machine (CachyOS 6.18) — all tests pass |
| **Ubuntu 24.04 LTS** | 6.8 | ✅ Verified | CI build matrix — compiles + tests pass |
| **Ubuntu 22.04 LTS** | 5.15 | ✅ Verified | CI build matrix — compiles + tests pass |
| **Fedora 44** | 6.19 | ✅ Verified | Real enforcement tested (firefox 100kb → 690 Kbps) |
| **Debian 13** | 6.12 | ✅ Verified | Real enforcement tested (firefox-esr 900kb → 7.0 Mbps) |
| **Ubuntu 21.10** | 5.13 | ✅ Verified | Minimum kernel — MUSL binary, all tests pass |
| **CachyOS VM** | 7.1 | ✅ Verified | MUSL binary, chromium 360kb → 3.0 Mbps (98%) |
| **openSUSE Tumbleweed** | 6.x | ⚠️ Should work | Not yet tested |
| **CentOS Stream 9** | 5.14 | ⚠️ Should work | Edge case (5.14 > 5.13 minimum) |
| **Alpine** | 6.x | ⚠️ Should work | musl libc — may need testing |

## Testing Matrix (v5.0.0)

### Kernels — all verified ✅
- [x] 5.13 (minimum — Ubuntu 21.10, MUSL binary)
- [x] 6.1 LTS (Debian 13)
- [x] 6.8 (Ubuntu 24.04 LTS)
- [x] 6.12 (Debian 13)
- [x] 6.15 (Ubuntu 26.04)
- [x] 6.18 (Arch Linux — dev machine)
- [x] 6.19 (Fedora 44)
- [x] 7.1 (CachyOS VM)

### Hardware
- [x] AMD (dev machine — Ryzen 7 5800HS, verified)
- [ ] Intel (not yet tested)
- [ ] ARM64 (future — no cross-compile yet)

### Network
- [x] WiFi (dev machine — verified, wlp1s0)
- [ ] Ethernet (not yet tested)
- [ ] Multiple interfaces (not yet tested)

### Binary types
- [x] GNU (glibc, dynamic) — Arch, Ubuntu, Fedora, Debian
- [x] MUSL (static) — Ubuntu 21.10, CachyOS VM, Debian 13

### Test coverage
- [x] 17/17 depth tests pass on all 6 distros
- [x] 13/13 leak tests pass on all 6 distros
- [x] Real enforcement verified on all 6 distros
- [x] Crash recovery test suite (9 tests)
- [x] Regression test runner (consolidated)

## Known Limitations

1. **cgroup v1 systems**: Not supported. zelynic will error on attach.
2. **Kernel < 5.13**: `cgroup.id` file missing. Identity resolution falls back
   to `stat()` inode, which may not match BPF cgroup ID on all systems.
3. **No BPF fs mounted**: Fire-and-forget mode (pin maps) will fail.
   Fix: `sudo mount -t bpf bpf /sys/fs/bpf`
4. **Non-root**: BPF operations require root. Use `sudo`.
5. **Container environments**: May need `--privileged` or specific capabilities.

## Troubleshooting

### "cgroup v2 not found at /sys/fs/cgroup"
Your system uses cgroup v1. Check:
```bash
stat -fc %T /sys/fs/cgroup
# Should output: cgroup2fs
```

### "BPF object file not found"
Compile BPF programs:
```bash
clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o
clang -O2 -g -target bpf -c bpf/observer.bpf.c -o bpf/observer.bpf.o
```

### "Failed to pin map"
BPF filesystem not mounted:
```bash
sudo mkdir -p /sys/fs/bpf
sudo mount -t bpf bpf /sys/fs/bpf
```

### BPF verifier rejects program
Check kernel version — `bpf_skb_cgroup_id()` requires 4.18+.
Some older kernels have stricter verifier. Check dmesg for verifier log.
