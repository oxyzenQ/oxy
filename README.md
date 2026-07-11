<p align="center">
  <img src="assets/zelynic-logo-master.png" alt="zelynic logo" width="260">
</p>

<h1 align="center">zelynic</h1>

<p align="center">
  <strong>Per-app network rate limiter for Linux.</strong>
</p>

<p align="center">
  Pure eBPF enforcement — no <code>tc</code>, no <code>nftables</code>, no <code>systemd-wrapper</code>.<br>
  One of the first open-source Linux bandwidth managers built around a pure eBPF datapath with per-application rate limiting.
</p>

<p align="center">
  <a href="https://ko-fi.com/rezky">
    <img src="https://img.shields.io/badge/Ko--fi-support-7C3AED?style=flat-square&logo=kofi&logoColor=white&labelColor=111827" alt="Support on Ko-fi">
  </a>
</p>

---

## What is zelynic?

zelynic limits any app's download/upload speed using **eBPF** — the Linux kernel's
built-in programmable packet filter. No external tools, no wrapper coordination,
no daemon. Just pure kernel enforcement.

```
$ sudo zelynic strict-single brave 100kb
Limiting 'brave' to 97.7 KB /s + 97.7 KB /s (2 policies, active in background)
Run 'zelynic unstrict brave' to remove, 'zelynic status' to check.
$ echo $?
0
# brave is now limited to 100 KB/s download + upload — persists in background
```

## Why zelynic?

| Traditional tools | zelynic |
|-------------------|---------|
| `tc` — per-interface shaping | Per-app (per-cgroup) shaping |
| `nftables` — packet marking | Direct eBPF token bucket |
| `wondershaper` — global limit | Individual app limits |
| `trickle` — LD_PRELOAD hack | Kernel-level enforcement |

**Key difference**: zelynic limits **individual applications**, not interfaces.
Brave can be limited to 100 KB/s while Firefox runs at full speed — all on the
same WiFi interface.

## Quick Start

### Prerequisites

- Linux kernel 5.13+ (cgroup v2 + `cgroup.id` file)
- Root access (BPF requires `CAP_BPF`)
- `clang` (compile BPF programs)
- `libbpf-dev` (BPF headers)

### Build

```bash
git clone https://github.com/oxyzenQ/zelynic.git
cd zelynic
git checkout dragon-architecture

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

# Check active limits
sudo zelynic status

# List apps with cgroup IDs
sudo zelynic list-apps

# Remove one app's limit
sudo zelynic unstrict brave

# Remove ALL limits (emergency)
sudo zelynic unstrict-all

# Real-time traffic monitor
sudo zelynic observe --interval 5

# Check eBPF support
zelynic doctor
```

## Rate Formats

Lowercase units only:

| Format | Meaning |
|--------|---------|
| `500b` | 500 bytes/second |
| `100kb` | 100 kilobytes/second |
| `1mb` | 1 megabyte/second |
| `1gb` | 1 gigabyte/second |
| `1000000` | Plain number = bytes/second |

**Bounds**: minimum 1 KB/s, maximum 100 GB/s. Both bounds can be overridden with `--allow-dangerous`.

## Safety Features

- **Min-rate guard**: rejects rates below 1 KB/s (prevents bricking apps)
- **Max-rate guard**: rejects rates above 100 GB/s (unreasonable defaults)
- **Fire-and-forget**: `strict-single` exits 0, limit persists in background
- **No residue**: `unstrict-all` removes all pin files + directory
- **Fail-safe BPF**: returns "allow" on any error path (never blocks on failure)
- **Dangerous target protection**: 53 system processes blocked by default
- **Overflow detection**: absurd rates show friendly warning, not wrapped values
- **Crash recovery**: `zelynic recover` detects + cleans orphaned BPF pins

## Architecture

**Dragon Architecture** — pure eBPF, single hooking layer:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 4 — Presentation (CLI)                           │
│  strict-single / strict-multi / status / unstrict       │
├─────────────────────────────────────────────────────────┤
│  Layer 3 — Aggregation (delta computation, sorting)     │
├─────────────────────────────────────────────────────────┤
│  Layer 2 — Identity Resolution (/proc → cgroup ID)      │
├─────────────────────────────────────────────────────────┤
│  Layer 1 — Map Interface (aya, pinned maps)             │
├─────────────────────────────────────────────────────────┤
│  Layer 0 — BPF Programs (kernel)                        │
│  cgroup_skb/ingress (download) + cgroup_skb/egress (upload) │
└─────────────────────────────────────────────────────────┘
```

See [docs/DRAGON_ARCHITECTURE.md](docs/DRAGON_ARCHITECTURE.md) for full design.

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

This is intentional. Many projects break after adding "too many features".
zelynic stays small on purpose.

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
- [Migration to v4.0](docs/MIGRATION_V4.md) — v3.x → v4.0 guide
- [Stress Test](scripts/stress-test.sh) — long-running enforcement test
- [Benchmark](scripts/benchmark.sh) — CPU/memory overhead measurement

## Test Results

Real test results (Arch Linux, kernel 6.18, AMD Ryzen 7 5800HS):

| App | Target | Actual Download | Actual Upload | Status |
|-----|--------|-----------------|---------------|--------|
| Chromium | -d 100kb -u 500kb | 670 Kbps (83 KB/s) | 3.5 Mbps | ✅ Working |
| Brave | -d 100kb -u 500kb | 730 Kbps (91 KB/s) | 4.3 Mbps | ✅ Working |
| aria2c | 500→100→10→2kb | Override each time | — | ✅ Override works |

CPU/memory: negligible (serve child < 1% CPU, < 10 MB RAM).

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
# openssl's -shake256 default output length varies; Python is consistent
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
