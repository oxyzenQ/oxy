# Verifier Compatibility

> BPF verifier assumptions, instruction limits, and kernel compatibility.

## Minimum Kernel: 5.13

zelynic requires **kernel 5.13+** for:
- `cgroup.id` file at `/sys/fs/cgroup{path}/cgroup.id` (identity resolution)
- cgroup v2 unified hierarchy (practical since 5.0, stable since 5.13)

## BPF Helper Dependencies

| Helper | Minimum Kernel | Used By |
|--------|---------------|---------|
| `bpf_ktime_get_ns()` | 4.18+ | Watchdog + token bucket refill |
| `bpf_skb_cgroup_id(skb)` | 4.18+ | Cgroup attribution (CRITICAL) |
| `bpf_map_lookup_elem()` | 4.18+ | All map reads |
| `bpf_map_update_elem()` | 4.18+ | All map writes |
| `bpf_get_current_comm()` | 4.18+ | Observer event comm field |

## Verifier Constraints

### Instruction Limit
- **Pre-5.2**: 4096 instructions (zelynic BPF programs ~200 instructions — safe)
- **5.2+**: 1 million instructions (bpf2bpf calls supported)
- zelynic uses `static __always_inline` functions — no bpf2bpf calls needed

### Stack Usage
- BPF stack limit: 512 bytes per frame
- zelynic stack usage: ~200 bytes (struct policy + struct bucket + locals)
- **Safe**: well under 512 byte limit

### Bounded Loops
- zelynic BPF programs have **NO loops** — all linear code paths
- Verifier guarantees termination (trivially — no branches that loop back)

### Map Access Patterns
All map accesses use bounds-checked patterns:
```c
// Pattern 1: lookup + null check
struct policy *pol = bpf_map_lookup_elem(&cgroup_policy_dl, &cgroup_id);
if (!pol) return 1;  // fail-safe

// Pattern 2: lookup-or-create
struct bucket *bkt = bpf_map_lookup_elem(&cgroup_bucket_dl, &cgroup_id);
if (!bkt) {
    struct bucket init = {};
    bpf_map_update_elem(&cgroup_bucket_dl, &cgroup_id, &init, BPF_ANY);
    bkt = bpf_map_lookup_elem(&cgroup_bucket_dl, &cgroup_id);
    if (!bkt) return 1;  // fail-safe
}
```

### Pointer Bounds
- All pointer dereferences bounds-checked by verifier
- `data_end` check before IP header parse (observer only)
- No variable-offset accesses

## Map Specifications

| Map | Type | Max Entries | Key Size | Value Size |
|-----|------|-------------|----------|------------|
| `cgroup_policy_dl` | HASH | 1024 | 4 (u32) | 24 (PolicyRaw) |
| `cgroup_policy_ul` | HASH | 1024 | 4 (u32) | 24 (PolicyRaw) |
| `cgroup_bucket_dl` | HASH | 1024 | 4 (u32) | 16 (BucketRaw) |
| `cgroup_bucket_ul` | HASH | 1024 | 4 (u32) | 16 (BucketRaw) |
| `group_bucket_dl` | HASH | 256 | 4 (u32) | 16 (BucketRaw) |
| `group_bucket_ul` | HASH | 256 | 4 (u32) | 16 (BucketRaw) |
| `cgroup_limiter_stats` | HASH | 1024 | 4 (u32) | 32 (LimiterStatsRaw) |
| `watchdog_deadline` | ARRAY | 1 | 4 (u32) | 8 (u64) |

## Overflow Safety

Token bucket calculation: `(elapsed_ns * rate_bps) / NS_PER_SEC`

- `elapsed_ns` capped at 1e9 (1 second) — prevents overflow
- Max product: `1e9 * 1e9 = 1e18` — fits in u64 (max ~1.8e19)
- Overflow at: rate_bps ≈ 1.8e10 (18 GB/s = 144 Gbps) — well beyond practical use

## Kernel Testing Matrix

| Kernel | Status | Notes |
|--------|--------|-------|
| 5.13 | ⚠️ Untested | Minimum — cgroup.id available |
| 6.1 LTS | ⚠️ Untested | Common server kernel |
| 6.6 LTS | ⚠️ Untested | Latest LTS |
| 6.12+ | ⚠️ Untested | Recent stable |
| 6.18 (CachyOS) | ✅ Verified | User's machine, 17/17 tests pass |

## Verifier Log

If BPF program is rejected by verifier, check:
```bash
sudo dmesg | grep -i bpf | tail -20
```

Common rejection causes:
1. **"invalid bpf_context access"** — wrong skb field access (fixed: use `bpf_skb_cgroup_id`)
2. **"back-edge from"** — loop detected (zelynic has no loops — shouldn't happen)
3. **"stack frame too large"** — >512 bytes stack (zelynic uses ~200 — safe)
4. **"unknown func"** — helper not available on kernel version
