// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF limiter — cgroup_skb egress token-bucket rate enforcer
//
// Wolf Architecture Layer 0: Enforcement.
// Pure eBPF. No tc, no nft, no cgroup-wrapper. The kernel enforces.
//
// Build: clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o
//
// Algorithm: token bucket per cgroup.
//   - cgroup_policy map: cgroup_id → {rate_bps, burst_bytes}
//   - cgroup_bucket map: cgroup_id → {tokens, last_refill_ns}
//   - On each egress packet:
//       1. Look up policy. No policy → allow (return 1).
//       2. Look up bucket. No bucket → initialize with full burst.
//       3. Refill: tokens += elapsed_ns * rate_bps / 1e9 (capped at burst).
//       4. If tokens >= pkt_len: deduct tokens, allow.
//       5. Else: update tokens (partial refill), drop (return 0).
//
// Fail-safe: any error (map lookup failure, bucket creation failure) → allow.
// Enforcement is a privilege; availability trumps enforcement on failure.
//
// Overflow safety: elapsed is capped at 1 second. With 1e9 ns * rate_bps,
// overflow occurs at ~18 GB/s (144 Gbps) — well beyond any practical use.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// Per-cgroup rate policy. Written by userspace, read by BPF.
struct policy {
    __u64 rate_bps;       // refill rate in bytes per second
    __u64 burst_bytes;    // maximum burst size in bytes
};

/// Per-cgroup token bucket state. Updated by BPF on every packet.
struct bucket {
    __u64 tokens;         // current token count in bytes
    __u64 last_refill_ns; // timestamp of last refill (bpf_ktime_get_ns)
};

/// Policy map: cgroup_id → {rate_bps, burst_bytes}.
/// Written by userspace via `zelynic ebpf enforce --limit`.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct policy);
} cgroup_policy SEC(".maps");

/// Bucket map: cgroup_id → {tokens, last_refill_ns}.
/// Managed entirely by BPF. Userspace reads for diagnostics.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct bucket);
} cgroup_bucket SEC(".maps");

/// Counter map: cgroup_id → {packets_allowed, packets_dropped, bytes_allowed, bytes_dropped}.
/// Lets userspace show enforcement statistics.
struct limiter_stats {
    __u64 packets_allowed;
    __u64 packets_dropped;
    __u64 bytes_allowed;
    __u64 bytes_dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct limiter_stats);
} cgroup_limiter_stats SEC(".maps");

/// Watchdog deadline — monotonic time (bpf_ktime_get_ns) after which the
/// BPF program becomes a no-op (returns 1 = allow all).
///
/// Userspace refreshes this every 200ms with a 30s timeout. If zelynic
/// crashes, freezes, or is kill -9'd, the watchdog expires within 30s
/// and all traffic resumes automatically — no manual intervention needed.
///
/// Fail-safe: if the map entry doesn't exist (before first refresh),
/// the program also allows all traffic.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);   // always 0
    __type(value, __u64); // deadline in nanoseconds (CLOCK_MONOTONIC)
} watchdog_deadline SEC(".maps");

/// 1 second in nanoseconds. Used to cap elapsed time and avoid overflow.
#define NS_PER_SEC 1000000000ULL

SEC("cgroup_skb/egress")
int enforce_limit(struct __sk_buff *skb) {
    // ━━ Watchdog check (fail-safe layer) ━━
    // If userspace is dead or hasn't set a deadline yet, allow all traffic.
    // This is the FIRST thing we check — before any policy lookup.
    __u32 zero = 0;
    __u64 *deadline = bpf_map_lookup_elem(&watchdog_deadline, &zero);
    if (!deadline) {
        return 1; // No watchdog set — fail safe.
    }
    __u64 now = bpf_ktime_get_ns();
    if (now > *deadline) {
        return 1; // Watchdog expired — userspace is dead. Allow all.
    }

    __u64 cgid = bpf_skb_cgroup_id(skb);
    __u32 cgroup_id = (__u32)cgid;
    __u32 pkt_len = skb->len;

    // Look up policy for this cgroup. No policy = unlimited = allow.
    struct policy *pol = bpf_map_lookup_elem(&cgroup_policy, &cgroup_id);
    if (!pol) {
        return 1;
    }

    // If rate is zero, treat as unlimited (fail safe — don't block everything).
    if (pol->rate_bps == 0) {
        return 1;
    }

    // Look up or create bucket.
    struct bucket *bkt = bpf_map_lookup_elem(&cgroup_bucket, &cgroup_id);
    if (!bkt) {
        // Initialize with full burst and current time (reuse `now` from above).
        struct bucket init = {};
        init.tokens = pol->burst_bytes;
        init.last_refill_ns = now;
        bpf_map_update_elem(&cgroup_bucket, &cgroup_id, &init, BPF_ANY);
        bkt = bpf_map_lookup_elem(&cgroup_bucket, &cgroup_id);
        if (!bkt) {
            // Can't create bucket — fail safe (allow).
            return 1;
        }
    }

    // Refill tokens based on elapsed time (reuse `now` from watchdog check).
    __u64 elapsed;
    if (now > bkt->last_refill_ns) {
        elapsed = now - bkt->last_refill_ns;
    } else {
        // Clock went backwards (shouldn't happen) — no refill.
        elapsed = 0;
    }

    // Cap elapsed at 1 second to prevent overflow in multiplication.
    // Max product: 1e9 * rate_bps. Overflow at rate_bps ≈ 1.8e10 (18 GB/s).
    if (elapsed > NS_PER_SEC) {
        elapsed = NS_PER_SEC;
    }

    // Calculate refill: (elapsed_ns * rate_bps) / 1e9 = bytes to add.
    __u64 refill = 0;
    if (elapsed > 0) {
        refill = (elapsed * pol->rate_bps) / NS_PER_SEC;
    }

    // New token count, capped at burst.
    __u64 new_tokens = bkt->tokens + refill;
    if (new_tokens > pol->burst_bytes) {
        new_tokens = pol->burst_bytes;
    }

    // Update last_refill timestamp.
    bkt->last_refill_ns = now;

    // Look up or create stats for this cgroup.
    struct limiter_stats *stats = bpf_map_lookup_elem(&cgroup_limiter_stats, &cgroup_id);
    if (!stats) {
        struct limiter_stats init = {};
        bpf_map_update_elem(&cgroup_limiter_stats, &cgroup_id, &init, BPF_ANY);
        stats = bpf_map_lookup_elem(&cgroup_limiter_stats, &cgroup_id);
    }

    // Check if enough tokens for this packet.
    if (new_tokens >= pkt_len) {
        // Allow: deduct tokens.
        bkt->tokens = new_tokens - pkt_len;
        if (stats) {
            stats->packets_allowed += 1;
            stats->bytes_allowed += pkt_len;
        }
        return 1;
    } else {
        // Drop: don't deduct (tokens remain for next packet's partial chance).
        bkt->tokens = new_tokens;
        if (stats) {
            stats->packets_dropped += 1;
            stats->bytes_dropped += pkt_len;
        }
        return 0;
    }
}

char _license[] SEC("license") = "GPL";
