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
git checkout wolf-architecture

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

**Bounds**: minimum 1 KB/s, maximum 1 GB/s. Below minimum requires `--allow-dangerous`.

## Safety Features

- **Watchdog**: BPF auto-disables if zelynic crashes (default 30s timeout)
- **Min-rate guard**: rejects rates below 1 KB/s (prevents bricking apps)
- **Fire-and-forget**: `strict-single` exits 0, limit persists in background
- **No residue**: `unstrict-all` kills child + removes all pin files
- **Fail-safe BPF**: returns "allow" on any error path (never blocks on failure)

## Architecture

**Wolf Architecture** — pure eBPF, single hooking layer:

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

See [docs/WOLF_ARCHITECTURE.md](docs/WOLF_ARCHITECTURE.md) for full design.

## Branches

| Branch | Purpose | Status |
|--------|---------|--------|
| `main` | Legacy v3.x (tc/nft/systemd-wrapper) | Stable, maintained |
| `wolf-architecture` | Pure eBPF v4.0.0-alpha | Active development |

## Documentation

- [Wolf Architecture](docs/WOLF_ARCHITECTURE.md) — design + principles
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

# Quantum-resistant — SHAKE256 (NIST PQ standard, via openssl)
openssl dgst -shake256 zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz
# Compare hash with: cat zelynic-vX.Y.Z-linux-amd64-gnu.tar.gz.shake256
```

## License

GPL-3.0-only

## Author

**rezky_nightky (oxyzenQ)** — built with curiosity, not pressure.

---

<p align="center">
  <em>Clean safely. Explain every decision. Recover anything.</em>
</p>
