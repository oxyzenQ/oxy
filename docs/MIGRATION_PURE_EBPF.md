# Pure-eBPF Migration Plan

> Roadmap for deprecating `tc`/`nft`/`systemd-wrapper` code on the
> `wolf-architecture` branch. **Not started** — this is a planning document.

## Current State (v3.1.1)

The legacy zelynic uses three enforcement mechanisms coordinated in userspace:

| Mechanism | Code Path | LOC | Purpose |
|-----------|-----------|-----|---------|
| `tc` (traffic control) | `src/limiter/tc.rs` + `attach.rs` | ~1,500 | qdisc/class/htb shaping per interface |
| `nft` (nftables) | `src/limiter/nft.rs` | ~800 | mark packets for tc class selection |
| `systemd-wrapper` | `src/systemd_wrapper/**` | ~7,200 | move PIDs into cgroups, then shape via tc |
| `limiter` glue | `src/limiter/{mod,state,reapply,refresh,...}.rs` | ~3,500 | coordinate the above |
| `accounting` | `src/accounting/**` | ~3,200 | read `/proc/net/dev` + ledger persistence |
| `capabilities` | `src/capabilities/**` | ~700 | detect tc/nft/systemd availability |
| **Total legacy** | | **~17,000** | |

The `ebpf` module (Wolf Architecture) currently adds ~1,200 lines and is
**additive** — it doesn't yet replace any of the above.

## Target State (v4.0.0 — Wolf Architecture)

| Mechanism | Code Path | LOC | Purpose |
|-----------|-----------|-----|---------|
| eBPF observer | `bpf/observer.bpf.c` + `src/ebpf/loader.rs` | ~400 | cgroup_skb/egress counter |
| eBPF limiter | `bpf/limiter.bpf.c` + `src/ebpf/limiter.rs` | ~600 | token-bucket per-cgroup enforcement |
| eBPF identity | `src/ebpf/identity.rs` | ~300 | cgroup ID → process name |
| eBPF events (legacy) | `src/ebpf/events.rs` + `src/ebpf_legacy.rs` | ~200 | capability detection |
| CLI + commands | `src/cli.rs` + `src/commands/mod.rs` (slimmed) | ~2,000 | `ebpf observe` + `ebpf enforce` |
| **Total wolf** | | **~3,500** | |

Net reduction: **~13,500 lines** (79% codebase reduction).

## Migration Phases

### Phase W1 — Feature Parity (current)
- [x] Observer: cgroup_skb/egress counter with identity labels
- [x] Limiter: token-bucket per-cgroup enforcement
- [x] CLI: `zelynic ebpf observe` + `zelynic ebpf enforce`
- [ ] Ingress counter (cgroup_skb/ingress)
- [ ] Persistent policies via BPF map pinning (`/sys/fs/bpf/zelynic_*`)
- [ ] JSON output for tooling integration

**Exit criteria**: eBPF can do everything the legacy stack does, plus more.

### Phase W2 — Deprecation Notices
- [ ] Add `--legacy` flag to `strict`/`run`/`auto` commands (preserves tc/nft path)
- [ ] Default `strict`/`run`/`auto` to eBPF path when `--features ebpf` compiled
- [ ] Print deprecation warning when legacy path is used:
  ```
  WARNING: tc/nft enforcement is deprecated. Use 'zelynic ebpf enforce' instead.
  Legacy path will be removed in v5.0.0.
  ```
- [ ] Update README to recommend eBPF path

**Exit criteria**: users get a clear migration path; legacy still works.

### Phase W3 — Legacy Code Removal
- [ ] Delete `src/limiter/tc.rs`, `src/limiter/nft.rs`
- [ ] Delete `src/systemd_wrapper/**` (entire directory)
- [ ] Slim `src/limiter/mod.rs` to just eBPF dispatch
- [ ] Remove `tc`/`nft`/`systemd` capability detection from `src/capabilities/`
- [ ] Remove `ratatui`/`crossterm` deps if TUI is also dropped
- [ ] Update `Cargo.toml` to remove unused deps
- [ ] Update CI matrix: drop non-eBPF build target

**Exit criteria**: `cargo build --features ebpf` produces a pure-eBPF binary
with zero tc/nft/systemd-wrapper code.

### Phase W4 — v4.0.0 Release
- [ ] Version bump to 4.0.0
- [ ] Tag + release (after explicit user approval)
- [ ] AUR package update
- [ ] Migration guide in `docs/MIGRATION_V4.md`

## What Stays

- `src/accounting/` — `/proc/net/dev` reading is still useful for interface-level
  totals (eBPF is per-cgroup, not per-interface). Will be slimmed but not removed.
- `src/capabilities/` — kept but slimmed: only eBPF capability detection.
- `src/cli.rs` + `src/commands/` — kept but heavily slimmed.
- `src/profile.rs` — profile save/apply still useful, repointed to eBPF.
- `src/monitor.rs` — `list`/`watch` commands still useful, repointed to eBPF.

## What Goes

- `src/limiter/tc.rs` — replaced by `bpf/limiter.bpf.c`
- `src/limiter/nft.rs` — replaced by `bpf/limiter.bpf.c`
- `src/limiter/cgroup.rs` — replaced by `IdentityMap` (Layer 2)
- `src/limiter/process.rs` — replaced by `IdentityMap` (Layer 2)
- `src/limiter/attach.rs` — BPF attach is in `src/ebpf/limiter.rs`
- `src/limiter/cleanup.rs` — BPF detach is automatic (Drop impl)
- `src/limiter/state.rs` — BPF map IS the state
- `src/limiter/reapply.rs` — BPF program runs continuously, no reapply needed
- `src/limiter/refresh.rs` — same as above
- `src/limiter/prereq.rs` — replaced by `ebpf check` command
- `src/limiter/diagnostics.rs` — replaced by `ebpf enforce --stats-interval`
- `src/limiter/output.rs` — replaced by `CounterSummary::print()`
- `src/limiter/traffic_proof.rs` — BPF IS the proof
- `src/systemd_wrapper/**` — entirely replaced by `IdentityMap`
- `src/tui.rs` — drop if TUI is removed (not currently used by eBPF path)

## Risks

1. **BPF verifier rejection**: The limiter's token-bucket logic uses
   multiplication that could trip the verifier on older kernels. Mitigation:
   cap elapsed at 1s, document minimum kernel version (5.13+).

2. **cgroup v1 systems**: Wolf Architecture requires cgroup v2. cgroup v1
   systems will need to stay on `main` (v3.x). Mitigation: clear error message
   on `ebpf enforce` if cgroup v2 not detected.

3. **No ingress shaping yet**: BPF limiter currently only does egress. Legacy
   tc could shape both. Mitigation: add cgroup_skb/ingress in Phase W1.

4. **Persistent policies**: Currently ephemeral. Users running zelynic in a
   loop will lose policies on each restart. Mitigation: BPF map pinning in
   Phase W1.

5. **Root requirement**: eBPF requires root. Legacy tc/nft also required root,
   so no regression, but worth documenting.

## Non-Goals

- **No gradual migration within a single binary.** v4.0.0 is a clean break.
  Users who need tc/nft stay on v3.x.
- **No automatic policy translation.** Users moving from v3.x to v4.0.0 must
  re-express their profiles in eBPF terms (`--limit firefox:1MB/s`).
- **No backward-compatible CLI.** `zelynic strict` is gone in v4.0.0. Use
  `zelynic ebpf enforce` instead.
