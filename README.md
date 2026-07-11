<p align="center">
  <img src="assets/zelynic-logo-master.png" alt="zelynic logo" width="260">
</p>

<h1 align="center">zelynic</h1>

<p align="center">
  <strong>Per-app network rate limiter for Linux. Pure eBPF. Silent but killer.</strong>
</p>

<p align="center">
  One of the first open-source Linux bandwidth managers built around a pure eBPF datapath
  with per-application rate limiting, fractional precision, and zero-daemon enforcement.
</p>

<p align="center">
  <a href="https://ko-fi.com/rezky">
    <img src="https://img.shields.io/badge/Ko--fi-support-7C3AED?style=flat-square&logo=kofi&logoColor=white&labelColor=111827" alt="Support on Ko-fi">
  </a>
</p>

---

## Why zelynic?

Traditional tools limit interfaces. zelynic limits **applications**.

Brave can be limited to 100 KB/s while Firefox runs at full speed — all on the
same WiFi interface. No `tc`, no `nftables`, no `LD_PRELOAD`, no daemon.

### What makes zelynic sharp

| Edge | Detail |
|------|--------|
| **Pure eBPF datapath** | Zero intermediaries. The kernel IS the rate limiter. |
| **Pinned bpf_links** | Enforcement survives process exit. No daemon, no battery drain. |
| **Fractional precision** | 0.00% rate error. Sub-byte token accumulation. Others lose ~0.7%. |
| **Schema migration** | BPF struct changes auto-detected + auto-cleaned on upgrade. |
| **Crash recovery** | `zelynic recover` detects + removes orphaned BPF pins. File lock prevents corruption. |
| **Discovery workflow** | `zelynic top --live` finds bandwidth hogs. Other limiters can't discover. |
| **Alt screen mode** | Clean terminal like htop. Zero trace on exit. No scrollback pollution. |

### vs traditional tools

| Tool | Technology | Per-app? | Daemon? | Precision |
|------|-----------|----------|---------|-----------|
| `tc` | HTB/TBF qdisc | Per-interface | No | Integer |
| `nftables` + `tc` | Mark + shape | Complex setup | No | Integer |
| `wondershaper` | tc wrapper | Global only | No | Integer |
| `trickle` | LD_PRELOAD | Dynamic only | No | Integer |
| **zelynic** | **Pure eBPF** | **Per-cgroup** | **No** | **0.00%** |

## Quick Start

### Prerequisites

- Linux kernel 5.13+ (cgroup v2 + `cgroup.id` file + bpf_link support)
- Root access (BPF requires `CAP_BPF`)
- `clang` (compile BPF programs)
- `libbpf-dev` (BPF headers)

### Build

```bash
git clone https://github.com/oxyzenQ/zelynic.git
cd zelynic

# Compile BPF programs
clang -O2 -g -target bpf -c bpf/observer.bpf.c -o bpf/observer.bpf.o
clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o

# Build Rust binary
cargo build --release --features ebpf
```

### Usage

```bash
# Limit a single app (both download + upload = 100kb)
sudo zelynic strict-single brave 100kb

# Limit per-direction
sudo zelynic strict-single firefox -d 1mb -u 500kb

# Limit multiple apps sharing one rate (group limit)
sudo zelynic strict-multi brave:curl:pacman 1mb

# Limit ALL user apps
sudo zelynic limit-all 500kb

# Find what's eating your bandwidth (10s snapshot)
sudo zelynic top

# Live tracking — catches bursty apps (q/ESC/Ctrl+C to quit)
sudo zelynic top --live 0

# Monitor traffic in alt screen (UL + DL, clean terminal)
sudo zelynic observe

# Block an app from internet entirely
sudo zelynic block-single brave
sudo zelynic unblock brave

# Check active limits
sudo zelynic status

# JSON output (for scripts)
sudo zelynic status --print-json | jq '.limits[]'

# Remove one app's limit
sudo zelynic unstrict brave

# Remove ALL limits (emergency)
sudo zelynic unstrict-all

# Recover from crash (clean orphaned pins)
sudo zelynic recover

# Check eBPF support
sudo zelynic doctor
```

## Commands

```
strict-single <target> [rate] [-d <rate>] [-u <rate>] [--allow-dangerous] [--force]
strict-multi  <a:b:c>  [rate] [-d <rate>] [-u <rate>] [--allow-dangerous] [--force]
limit-all              [rate] [-d <rate>] [-u <rate>] [--allow-dangerous] [--force]
block-single <target> [--force]
block-multi  <a:b:c>   [--force]
block-all              [--force]
unstrict <target>
unblock <target>
unstrict-all
recover
status [--print-json]
list-apps [--print-json]
observe [--live <dur>] [--cgroup <id>]
top [--duration <dur>] [--live <dur>] [--limit N]
doctor [--print-json]
completions <shell>
man
```

## Rate Formats

Lowercase units only (decimal SI: 1 KB = 1000 bytes):

| Format | Meaning |
|--------|---------|
| `500b` | 500 bytes/second |
| `100kb` | 100 kilobytes/second |
| `1mb` | 1 megabyte/second |
| `1gb` | 1 gigabyte/second |
| `100gb` | 100 gigabytes/second |

**Bounds**: minimum 1 KB/s, maximum 100 GB/s. Both overridable with `--allow-dangerous`.

## Time Durations

For `--live` and `--duration` flags:

| Format | Meaning |
|--------|---------|
| `1s` | 1 second |
| `3m` | 3 minutes |
| `10h` | 10 hours |
| `0` | forever (until q/ESC/Ctrl+C) |

## Safety Features

- **Min-rate guard**: rejects rates below 1 KB/s (prevents bricking apps)
- **Max-rate guard**: rejects rates above 100 GB/s (unreasonable defaults)
- **Fire-and-forget**: `strict-single` exits 0, limit persists in background
- **No residue**: `unstrict-all` removes all pin files + directory
- **Fail-safe BPF**: returns "allow" on any error path (never blocks on failure)
- **Dangerous target protection**: 53 system processes blocked by default
- **Overflow detection**: absurd rates show friendly warning, not wrapped values
- **Crash recovery**: `zelynic recover` detects + cleans orphaned BPF pins
- **File lock**: prevents concurrent operations from corrupting BPF state
- **Schema migration**: BPF struct changes auto-detected + auto-cleaned on upgrade
- **Kernel version detection**: graceful fallback for kernel < 5.7 (legacy bpf_prog_attach)

## Architecture

**Dragon Architecture** — pure eBPF, no intermediaries:

```
┌───────────────────────────────────────────────────┐
│  Layer 4 — CLI                                    │
│  strict-single / block / top / observe / status   │
├───────────────────────────────────────────────────┤
│  Layer 3 — Aggregation (delta, sort, format)      │
├───────────────────────────────────────────────────┤
│  Layer 2 — Identity (/proc → cgroup ID)           │
├───────────────────────────────────────────────────┤
│  Layer 1 — Map Interface (aya, pinned maps)       │
├───────────────────────────────────────────────────┤
│  Layer 0 — BPF (kernel)                           │
│  cgroup_skb/ingress + cgroup_skb/egress           │
└───────────────────────────────────────────────────┘
```

## Philosophy

**Stable, strong, boring, easy maintenance, silent but killer.**

zelynic is a Linux utility that is simple from the user's perspective,
but powerful under the hood. The interface rarely changes. Features don't
explode. Every release makes it slightly more stable, slightly faster,
slightly easier to maintain.

### What zelynic IS

- ✅ **Single CLI binary** — no daemon, no service, no config file
- ✅ **Pure eBPF** — no tc, no nft, no wrappers
- ✅ **Small codebase** — minimal dependencies, easy to audit
- ✅ **Predictable behavior** — same input → same output, every time
- ✅ **Linux-first** — BSD/macOS source support OK, Windows never

### What zelynic will NEVER be

- ❌ No TUI (terminal user interface)
- ❌ No systemd service dependency
- ❌ No `config.toml` (CLI flags only)
- ❌ No daemon mode
- ❌ No REST API
- ❌ No Windows support

### Stable API (from v10.0.0)

Starting with v10.0.0, the CLI surface is frozen. No breaking changes
to commands, flags, or output format. Future releases focus on:
- Bug fixes
- Kernel compatibility updates
- Performance improvements (internal, no API changes)

### Maintenance Mode (from v10.0.0)

> **Zelynic v10 marks the beginning of maintenance mode. Future releases
> prioritize stability, compatibility, performance, and bug fixes over
> feature expansion.**

No new features unless critical for security or compatibility.
Release cadence slows to "when needed".

## Branches

| Branch | Purpose | Status |
|--------|---------|--------|
| `main` | Pure eBPF v10.x (Dragon Architecture) | Maintenance mode |
| `legacy` | v3.1.1 (tc/nft/systemd-wrapper) | Final legacy release, no new development |

## Documentation

- [Dragon Architecture](docs/DRAGON_ARCHITECTURE.md) — design + principles
- [Kernel Compatibility](docs/KERNEL_COMPATIBILITY.md) — requirements + distro matrix
- [Performance Metrics](docs/PERFORMANCE.md) — deep benchmark results + targets
- [Migration to v4.0](docs/MIGRATION_V4.md) — v3.x → v4.0 guide
- [Release Verification](docs/VERIFY_RELEASE.md) — checksum verification

## Test Results

Verified on 6 distributions (all pass 17/17 depth + 13/13 leak tests):

| Distro | Kernel | Binary | Enforcement |
|--------|--------|--------|-------------|
| Arch Linux | 6.18 | GNU | brave 100kb → 730 Kbps |
| CachyOS VM | 7.1 | MUSL | chromium 360kb → 3.0 Mbps |
| Ubuntu 26.04 | 6.15 | GNU | firefox 100kb → 650 Kbps |
| Fedora 44 | 6.19 | GNU | firefox 100kb → 690 Kbps |
| Ubuntu 21.10 | 5.13 | MUSL | GeckoMain 100kb → 770 Kbps |
| Debian 13 | 6.12 | MUSL | firefox-esr 900kb → 7.0 Mbps |

## Release Verification

Each release ships **three** checksums: classical SHA-512 + quantum-resistant
BLAKE2b-512 + SHAKE256. Full instructions in
[docs/VERIFY_RELEASE.md](docs/VERIFY_RELEASE.md).

```bash
# Classical (universal)
sha512sum -c zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz.sha512sum

# Quantum-resistant — BLAKE2b (fastest, in coreutils)
b2sum -c zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz.b2sum

# Quantum-resistant — SHAKE256 (NIST PQ standard, via Python)
COMPUTED=$(python3 -c "import hashlib; print(hashlib.shake_256(open('zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz','rb').read()).hexdigest(64))")
EXPECTED=$(awk '{print $1}' zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz.shake256)
[ "$COMPUTED" = "$EXPECTED" ] && echo "OK" || echo "FAILED"
```

## License

GPL-3.0-only

## Author

**rezky_nightky (oxyzenQ)** — built with curiosity, not pressure.

---

<p align="center">
  <em>Simple from the user's perspective. Powerful under the hood.</em>
</p>
