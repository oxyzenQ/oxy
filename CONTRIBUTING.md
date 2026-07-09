# Contributing to zelynic

Thank you for your interest in contributing to zelynic! This document covers
the build process, project structure, and coding standards.

## Prerequisites

- Rust 1.88+ (stable)
- clang 10+ (compile BPF programs)
- libbpf-dev (BPF headers)
- linux-libc-dev (multiarch kernel headers)
- Linux kernel 5.13+ (cgroup v2 + cgroup.id file)

## Build

```bash
# Compile BPF programs
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
  -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
  -c bpf/observer.bpf.c -o bpf/observer.bpf.o

# Build Rust binary
cargo build --release --features ebpf
```

## Project Structure

```
src/
  main.rs              — entry point
  cli.rs               — CLI definition (clap)
  commands/mod.rs      — command dispatchers
  commands/help.rs     — --help-all output
  commands/backend.rs  — completions + man page
  ebpf/
    mod.rs             — module exports
    limiter.rs         — Limiter struct + BPF map operations
    limiter_types.rs   — types, constants, helper functions
    identity.rs        — cgroup ID → process name resolution
    loader.rs          — observer BPF loader
    audit.rs           — JSONL audit log
  ebpf_legacy.rs       — kernel capability detection
  capabilities/mod.rs  — eBPF support check (doctor)
  info.rs              — version + build info
  update.rs            — --check-update

bpf/
  limiter.bpf.c        — token-bucket enforcer (ingress + egress)
  observer.bpf.c       — traffic counter (egress)

scripts/
  build.sh             — check-all orchestration
  check-policy.py      — LOC + copyright + SPDX check
  stress-test.sh       — 6-test stress suite
  leak-test.sh         — orphan detection after every operation
  distros-depth-test.sh — 17-test comprehensive suite
  long-endurance-test.sh — 24h continuous enforcement
  benchmark.sh         — CPU/memory overhead measurement
```

## Coding Standards

1. **LOC limit**: < 1000 lines per file (enforced by `check-policy.py`)
2. **Copyright + SPDX**: every source file must have:
   ```
   // Copyright (C) 2026 rezky_nightky
   // SPDX-License-Identifier: GPL-3.0-only
   ```
3. **License**: GPL-3.0-only
4. **No tc/nft/systemd-wrapper**: pure eBPF only on `dragon-architecture` branch
5. **Fail-safe**: BPF programs return 1 (allow) on every error path
6. **Lowercase units**: rate formats use `kb`, `mb`, `gb` (no uppercase, no `/s`)

## Pre-commit

```bash
./scripts/build.sh check-all
```

This runs: cargo fmt --check, cargo clippy --all-features -D warnings,
cargo test --locked, cargo deny check all, python3 scripts/check-policy.py,
yamllint, codespell, actionlint.

## Branch Strategy

- `main` — legacy v3.x (tc/nft/systemd-wrapper). Stable, maintained.
- `dragon-architecture` — pure eBPF v4.0.0-alpha. Active development.
