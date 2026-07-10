// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF observer — cgroup_skb egress traffic counter
//
// Build: clang -O2 -g -target bpf -c bpf/observer.bpf.c -o bpf/observer.bpf.o

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define EVENT_PACKET 1

struct event {
    __u32 event_type;
    __u32 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u16 protocol;
    __u16 direction;
    __u32 pkt_len;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    char comm[16];
};

// Ring buffer — 2MB for high traffic bursts
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} events SEC(".maps");

// Per-cgroup counters
struct cgroup_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_event_packet; // packet count at last event emission
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct cgroup_stats);
} cgroup_counters SEC(".maps");

SEC("cgroup_skb/egress")
int observe_egress(struct __sk_buff *skb) {
    __u64 cgid      = bpf_skb_cgroup_id(skb);
    __u32 cgroup_id = (__u32)cgid;
    __u64 pid_tgid  = bpf_get_current_pid_tgid();
    __u32 pid       = pid_tgid >> 32;
    __u32 uid       = bpf_get_current_uid_gid();
    __u32 pkt_len   = skb->len;

    // Update counters — use BPF_ANY to create if missing
    struct cgroup_stats *stats =
        bpf_map_lookup_elem(&cgroup_counters, &cgroup_id);
    if (stats) {
        stats->packets += 1;
        stats->bytes += pkt_len;
    } else {
        struct cgroup_stats init = {};
        init.packets             = 1;
        init.bytes               = pkt_len;
        bpf_map_update_elem(&cgroup_counters, &cgroup_id, &init, BPF_ANY);
        stats = bpf_map_lookup_elem(&cgroup_counters, &cgroup_id);
        if (!stats)
            return 1;
    }

    // Throttle: emit 1 event per 100 packets per cgroup
    // Use last_event_packet to track when we last emitted
    if (stats->packets - stats->last_event_packet < 100) {
        return 1;
    }
    stats->last_event_packet = stats->packets;

    // Parse IP header (cgroup_skb has NO Ethernet header)
    __u16 protocol = 0;
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;

    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        void *data_end    = (void *)(long)skb->data_end;
        struct iphdr *iph = (void *)(long)skb->data;
        if ((void *)(iph + 1) > data_end)
            return 1;

        protocol = iph->protocol;
        src_ip   = iph->saddr;
        dst_ip   = iph->daddr;

        if (protocol == 6 || protocol == 17) {
            void *transport = (void *)(iph + 1);
            if (protocol == 6) {
                struct tcphdr *tcp = transport;
                if ((void *)(tcp + 1) <= data_end) {
                    src_port = bpf_ntohs(tcp->source);
                    dst_port = bpf_ntohs(tcp->dest);
                }
            } else {
                struct udphdr *udp = transport;
                if ((void *)(udp + 1) <= data_end) {
                    src_port = bpf_ntohs(udp->source);
                    dst_port = bpf_ntohs(udp->dest);
                }
            }
        }
    }

    // Emit event
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 1;

    e->event_type = EVENT_PACKET;
    e->cgroup_id  = cgroup_id;
    e->pid        = pid;
    e->uid        = uid;
    e->protocol   = protocol;
    e->direction  = 0;
    e->pkt_len    = pkt_len;
    e->src_ip     = src_ip;
    e->dst_ip     = dst_ip;
    e->src_port   = src_port;
    e->dst_port   = dst_port;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return 1;
}

char _license[] SEC("license") = "GPL";
