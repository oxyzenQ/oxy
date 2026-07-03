# Kernel Compatibility

> Requirements for running zelynic v4.0.0-alpha (Wolf Architecture).

## Minimum Requirements

| Component | Minimum | Recommended | Why |
|-----------|---------|-------------|-----|
| **Kernel** | 5.13+ | 6.6 LTS+ | `cgroup.id` file (5.13+), `bpf_skb_cgroup_id()` (4.18+) |
| **cgroup** | v2 only | v2 only | zelynic uses `cgroup_skb/egress` + `ingress` hooks |
| **BPF fs** | Mounted at `/sys/fs/bpf` | Mounted | Required for map pinning (fire-and-forget mode) |
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

## Distro Compatibility

| Distro | Kernel | Status | Notes |
|--------|--------|--------|-------|
| **Arch Linux** | 6.x (latest) | ✅ Tested | User's dev machine (CachyOS 6.18) |
| **Ubuntu 22.04 LTS** | 5.15 | ⚠️ Untested | cgroup.id available (5.13+) |
| **Ubuntu 24.04 LTS** | 6.8 | ⚠️ Untested | Should work |
| **Fedora 40/41** | 6.x | ⚠️ Untested | Should work |
| **Debian 12** | 6.1 | ⚠️ Untested | Should work |
| **openSUSE Tumbleweed** | 6.x | ⚠️ Untested | Should work |
| **CentOS Stream 9** | 5.14 | ⚠️ Untested | Edge case (5.14 > 5.13) |
| **Alpine** | 6.x | ⚠️ Untested | musl libc — may need testing |

## Testing Matrix (TODO)

Before v4.0.0 release, test on:

### Kernels
- [ ] 5.13 (minimum)
- [ ] 6.1 LTS
- [ ] 6.6 LTS
- [ ] 6.12+
- [ ] 6.18 (user's machine — verified)

### Hardware
- [ ] AMD (user's machine — verified, Ryzen 7 5800HS)
- [ ] Intel
- [ ] ARM64 (future)

### Network
- [ ] WiFi (user's machine — verified, wlp1s0)
- [ ] Ethernet
- [ ] Multiple interfaces

### Distro
- [ ] Arch Linux (user's machine — verified)
- [ ] Ubuntu 24.04 LTS
- [ ] Fedora 41
- [ ] Debian 12

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
