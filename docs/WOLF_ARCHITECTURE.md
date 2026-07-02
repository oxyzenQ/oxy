# Wolf Architecture

> Pure eBPF. Single hooking layer. No combined tools. Linux-only.

## Why

zelynic's legacy stack mixed three enforcement mechanisms — `tc` (traffic
control qdiscs), `nft` (nftables), and `systemd-run` cgroup moves — to achieve
per-process network shaping. Each tool has its own:

- config format (qdisc class IDs vs nft chain names vs systemd unit properties)
- failure mode (tc silently drops rules on interface rename, nft requires root
  + cap_net_admin, systemd-run requires logind + PAM cooperation)
- observability gap (tc stats don't match nft counters don't match cgroup
  traffic — three numbers, none of them agree)

Coordinating three tools is a maintenance nightmare. Worse, it leaks: a `tc`
rule applied to `wlp1s0` survives a WiFi reconnect and silently shapes the
wrong interface. An `nft` chain survives a service restart and blocks traffic
to a process that no longer exists.

**Wolf Architecture eliminates the coordination problem by using exactly one
mechanism: eBPF.** The kernel already knows which cgroup sent each packet. BPF
lets us observe, count, and (future) shape that traffic in-kernel — no
userspace tool coordination, no format mismatches, no leaked state.

## Principles

1. **Pure eBPF.** All kernel-level operations are BPF programs. No `tc`, no
   `iptables`, no `nft`, no `systemd-run` cgroup tricks. If a feature can't be
   done in BPF, it doesn't belong in wolf-architecture zelynic.

2. **Single Hooking Layer.** All observation and enforcement happens at BPF
   hook points (`cgroup_skb`, `sock_ops`, `xdp`, `tc`-cls-act-BPF — but
   **never** `tc`-qdisc). One program type per concern. No multi-tool glue.

3. **Userspace-Composable.** BPF programs expose state via maps. Userspace
   reads maps, applies policy, writes back. **No daemons** — every zelynic
   invocation is a one-shot: attach BPF, do work, detach, exit.

4. **Fail-Safe by Design.** If userspace dies, BPF programs continue running
   with the last-known policy. If a BPF program errors, it returns `1` (allow)
   — never block traffic on failure. Shaping is a privilege, not a right;
   availability trumps enforcement.

5. **Observable, not Magic.** Every packet seen, every decision made, every
   byte counted. The observer is the source of truth — the limiter is a
   consumer of the observer's data. No black boxes, no "trust me bro"
   enforcement.

6. **Linux-First, Linux-Only.** No portable abstractions. cgroup v2, BPF, kernel ≥ 5.13.
   Embrace the platform. BSD/macOS source compiles but `ebpf` feature is
   no-op. Windows is not supported and never will be.

## Layered Structure

```
┌─────────────────────────────────────────────────────────┐
│  Layer 4 — Presentation                                 │
│  CLI / JSON / (future) TUI                              │
│  src/commands/, src/cli.rs                              │
├─────────────────────────────────────────────────────────┤
│  Layer 3 — Aggregation                                  │
│  delta computation, summary, sorting                    │
│  src/ebpf/loader.rs (CounterSummary)                    │
├─────────────────────────────────────────────────────────┤
│  Layer 2 — Identity Resolution (userspace)              │
│  cgroup ID → process name / uid / path                  │
│  src/ebpf/identity.rs (IdentityMap)                     │
├─────────────────────────────────────────────────────────┤
│  Layer 1 — Map Interface                                │
│  typed access to BPF maps (HashMap, RingBuf, PerCpu)    │
│  src/ebpf/loader.rs (read_counters, poll_events)        │
├─────────────────────────────────────────────────────────┤
│  Layer 0 — BPF Programs (kernel)                        │
│  cgroup_skb/egress observer → cgroup_counters map       │
│  bpf/observer.bpf.c                                     │
│  (future: limiter.bpf.c, policer.bpf.c)                 │
└─────────────────────────────────────────────────────────┘
```

### Layer 0 — BPF Programs (kernel)

The BPF program is the **only** kernel-level component. It hooks
`cgroup_skb/egress`, reads `bpf_get_current_cgroup_id()`, and updates a hash
map keyed by cgroup ID. Per-cgroup stats: packet count, byte count.

Contract:
- Program returns `1` (allow) on every path — never block.
- Map updates use `BPF_ANY` (create-or-update).
- No ring buffer spam: events throttled to 1 per 100 packets per cgroup.

### Layer 1 — Map Interface

Userspace reads BPF maps via `aya`. The map interface is typed:
`BpfHashMap<u32, CgroupStatsRaw>` — keys are cgroup IDs, values are the
`#[repr(C)]` struct that matches the BPF-side `struct cgroup_stats`.

This layer is the **only** place that touches BPF maps directly. Everything
above it works with Rust types.

### Layer 2 — Identity Resolution (userspace)

BPF returns raw cgroup IDs (`cg:73386`). Humans need `cg:73386 (firefox)`.
This layer walks `/proc/*/cgroup` + `/sys/fs/cgroup{path}/cgroup.id` to build
a reverse map: cgroup ID → `ProcessIdentity { pid, uid, comm, cgroup_path }`.

Refresh policy: 10s TTL by default. Refresh is best-effort — if `/proc` walk
fails, labels fall back to raw `cg:{id}`. The BPF program is unaffected.

### Layer 3 — Aggregation

`poll_and_summarize()` reads current map state, computes deltas against the
previous poll, and produces a `CounterSummary`. This is where rate
calculations, top-N sorting, and threshold detection live.

### Layer 4 — Presentation

CLI output (`CounterSummary::print()`), JSON output (future), TUI (future).
This layer never touches BPF directly — it consumes `CounterSummary` +
`IdentityMap` and renders.

## Roadmap (Wolf Architecture branch only)

This branch is the staging ground for the pure-eBPF rewrite. The legacy
`tc`/`nft`/`systemd-wrapper` code stays on `main` for the v3.x line.

### Done
- [x] Layer 0: `bpf/observer.bpf.c` — cgroup_skb/egress counter
- [x] Layer 1: `read_counters()` direct map read
- [x] Layer 2: `IdentityMap` with /proc reverse-lookup + 10s TTL refresh
- [x] Layer 3: `CounterSummary` with delta computation + sorting
- [x] Layer 4: `print(&IdentityMap)` with human-readable labels

### Next
- [ ] Layer 0: `bpf/limiter.bpf.c` — cgroup_skb/egress with token-bucket
      enforcement (per-cgroup rate limit, BPF-side)
- [ ] Layer 1: write path — `update_policy(cgroup_id, rate_bps)` writes to
      `cgroup_policy` map
- [ ] Layer 2: identity-aware policy — `zelynic limit --process firefox 1MB/s`
      resolves firefox's cgroup, writes policy
- [ ] Layer 4: `--json` output for tooling integration
- [ ] Layer 4: `--cgroup <id>` and `--min-bytes <N>` filters

### Future (post-v4.0)
- [ ] Layer 0: `bpf/policer.bpf.c` — DSCP marking via `sock_ops`
- [ ] Layer 0: XDP ingress counter (separate from cgroup_skb/egress)
- [ ] Layer 2: cgroup path → systemd unit name resolution
- [ ] Layer 4: TUI dashboard (ratatui, already a dependency)

## Non-Goals

- **No Windows support.** Ever.
- **No macOS/BSD support for the `ebpf` feature.** Source compiles, feature
  is no-op.
- **No daemon mode.** Every invocation is one-shot. If you want continuous
  monitoring, use a shell loop or systemd timer.
- **No combined-tool fallback.** If BPF can't do it, wolf-architecture zelynic
  doesn't do it. The legacy `tc`/`nft` code stays on `main` for users who
  need it, but this branch is pure eBPF.
- **No REST API / MCP / TUI-as-server.** CLI + config + exit codes. That's it.

## Branch Strategy

- `main` — legacy zelynic v3.x line (`tc`/`nft`/`systemd-wrapper`). Tagged
  releases continue here until wolf-architecture is production-ready.
- `wolf-architecture` — pure eBPF rewrite. No tags, no releases until
  limiter.bpf.c is proven stable and the legacy enforcement paths are
  deprecated.
- `intergalaxion` — archived (44 commits of planning docs, 0 BPF programs).
  Superseded by `wolf-architecture`.

## Naming

"Wolf Architecture" — because a wolf pack operates with clear layering:
scouts (observer), hunters (limiter), alpha (policy). Each role is distinct,
each contributes to the pack's survival. No member tries to do everything
alone.

Also: the agent persona behind this work is `wolfzen`. The architecture
inherits the name.
