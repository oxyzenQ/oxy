# Migration Guide: v3.x → v4.0

> How to migrate from legacy zelynic (tc/nft/systemd-wrapper) to Dragon Architecture (pure eBPF).

## Why Migrate?

| Aspect | v3.x (legacy) | v4.0 (Dragon Architecture) |
|--------|---------------|--------------------------|
| **Enforcement** | tc + nft + systemd-wrapper | Pure eBPF |
| **LOC** | ~17,000 | ~3,600 (79% reduction) |
| **Dependencies** | tc binary, nft binary, systemd | kernel 5.13+ only |
| **State leakage** | tc rules survive interface rename | BPF dies with process, zero residue |
| **Observability** | 3 counters that don't match | 1 source of truth (BPF maps) |
| **CLI** | 15+ commands | 4 commands (strict-single/multi, unstrict, status) |

## Prerequisites

- Linux kernel 5.13+ (was: any kernel with tc support)
- cgroup v2 (was: cgroup v1 or v2)
- Root access (same)
- `clang` + `libbpf-dev` (NEW — for BPF compilation)

Check compatibility:
```bash
zelynic doctor
```

## CLI Changes

### Removed Commands

These v3.x commands are **gone** in v4.0:

| v3.x Command | v4.0 Replacement |
|--------------|-------------------|
| `zelynic strict -d 500kb brave` | `zelynic strict-single brave 500kb` |
| `zelynic strict -d 500kb -u 100kb brave` | `zelynic strict-single brave -d 500kb -u 100kb` |
| `zelynic unstrict brave` | `zelynic unstrict brave` (same) |
| `zelynic status` | `zelynic status` (same) |
| `zelynic clean --all` | `zelynic unstrict-all` |
| `zelynic list` | `zelynic list-apps` |
| `zelynic profile save/apply/list/delete` | *(removed — use shell aliases)* |
| `zelynic qos high/low/status/reset` | *(removed — use strict-single)* |
| `zelynic run --target ...` | *(removed — systemd-wrapper gone)* |
| `zelynic auto ...` | *(removed — daemon mode gone)* |
| `zelynic watch ...` | `zelynic observe` |
| `zelynic ledger inspect/export` | *(removed — accounting gone)* |
| `zelynic usage --sample` | *(removed — use `zelynic observe`)* |
| `zelynic strict-run-lab` | *(removed — lab command gone)* |
| `zelynic --iface eth0` | *(removed — eBPF attaches to cgroup, not interface)* |

### New Commands

| v4.0 Command | Purpose |
|--------------|---------|
| `zelynic strict-single <target> <rate>` | Limit one app |
| `zelynic strict-multi <a:b:c> <rate>` | Limit group of apps (shared rate) |
| `zelynic unstrict-all` | Remove ALL limits (emergency) |
| `zelynic list-apps` | List apps with cgroup IDs |
| `zelynic observe` | Real-time traffic monitor |
| `zelynic doctor` | Check eBPF support |

### Rate Format Changes

| v3.x | v4.0 | Notes |
|------|------|-------|
| `500kb` | `500kb` | Same |
| `500KB/s` | `500kb` | Lowercase only, no `/s` suffix |
| `1mb` | `1mb` | Same |
| `1MB/s` | `1mb` | Lowercase only |
| `500kbit` | *(removed)* | Use `500kb` (bytes, not bits) |

## Migration Steps

### 1. Build v4.0

```bash
git clone https://github.com/oxyzenQ/zelynic.git
cd zelynic
git checkout dragon-architecture

# Compile BPF
clang -O2 -g -target bpf -c bpf/observer.bpf.c -o bpf/observer.bpf.o
clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o

# Build
cargo build --release --features ebpf
```

### 2. Remove v3.x limits

If you have active v3.x limits (tc rules, nft chains), remove them:

```bash
# Using v3.x binary
sudo zelynic clean --all

# Or manually
sudo nft flush ruleset
sudo tc qdisc del dev eth0 root 2>/dev/null
```

### 3. Re-apply limits with v4.0

```bash
# Before (v3.x):
sudo zelynic strict -d 500kb -u 100kb brave

# After (v4.0):
sudo zelynic strict-single brave -d 500kb -u 100kb
```

### 4. Update scripts

If you have scripts using v3.x CLI, update command names. The rate format also
changed (lowercase only, no `/s` suffix).

### 5. Migrate profiles

v3.x had `zelynic profile save/apply`. v4.0 removes this — use shell aliases:

```bash
# v3.x:
zelynic profile save gaming -d 50mb -u 50mb
zelynic profile apply gaming discord

# v4.0 (shell alias):
alias limit-gaming='sudo zelynic strict-single discord 50mb'
alias unlimit='sudo zelynic unstrict discord'
```

## What Stays the Same

- `zelynic -V` / `--version` (output format unchanged)
- `zelynic --check-update`
- `zelynic completions <shell>`
- `zelynic man`
- Root requirement
- GPL-3.0-only license

## Troubleshooting

### "No cgroup found for 'appname'"
The app isn't running, or its cgroup isn't detected. Check:
```bash
zelynic list-apps | grep appname
```

### "cgroup v2 not found at /sys/fs/cgroup"
Your system uses cgroup v1. v4.0 requires cgroup v2.
Stay on v3.x (`main` branch) if you need cgroup v1 support.

### "BPF object file not found"
Compile BPF programs:
```bash
clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o
```

### "Rate below minimum"
v4.0 enforces minimum 1 KB/s. Use `--allow-dangerous` to override:
```bash
sudo zelynic strict-single brave 500b --allow-dangerous
```

## Rollback

If v4.0 doesn't work for you, switch back to v3.x:

```bash
git checkout main
cargo build --release
```

Your v3.x limits (if any) are untouched by v4.0 — they use different mechanisms.
