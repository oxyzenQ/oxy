#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Benchmark: measure zelynic eBPF overhead (CPU + memory).
# Compares: no limit vs 1mb limit vs 100kb limit.
#
# Usage: sudo ./scripts/benchmark.sh [duration_seconds]
# Default: 30 seconds per test

set -euo pipefail

DURATION="${1:-30}"
BINARY="${BINARY:-./target/release/zelynic}"
BPF_OBJ="bpf/limiter.bpf.o"

if [[ $EUID -ne 0 ]]; then
    echo "This script requires root. Run with sudo."
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    cargo build --release --features ebpf
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o "$BPF_OBJ"
fi

echo "━━━ zelynic Benchmark (${DURATION}s per test) ━━━"
echo ""

# Start a background download process (curl to fast.com-like endpoint)
echo "Starting background download..."
curl -s -o /dev/null http://speedtest.tele2.net/10MB.zip &
CURL_PID=$!
CURL_COMM=$(cat /proc/$CURL_PID/comm 2>/dev/null || echo "curl")

measure_overhead() {
    local label="$1"
    local duration="$2"
    
    echo "  Measuring: $label (${duration}s)..."
    
    # Sample CPU + memory every 2 seconds
    local cpu_samples=()
    local mem_samples=()
    
    for i in $(seq 1 $((duration / 2))); do
        # Get zelynic serve child CPU + memory
        if [[ -f /tmp/zelynic.pid ]]; then
            local pid=$(cat /tmp/zelynic.pid)
            local stats=$(ps -p "$pid" -o %cpu,%rss --no-headers 2>/dev/null || echo "0 0")
            local cpu=$(echo "$stats" | awk '{print $1}')
            local mem_kb=$(echo "$stats" | awk '{print $2}')
            cpu_samples+=("$cpu")
            mem_samples+=("$mem_kb")
        else
            cpu_samples+=("0")
            mem_samples+=("0")
        fi
        sleep 2
    done
    
    # Calculate averages
    local cpu_sum=0
    local mem_sum=0
    local count=${#cpu_samples[@]}
    
    for i in "${!cpu_samples[@]}"; do
        cpu_sum=$(echo "$cpu_sum + ${cpu_samples[$i]}" | bc -l 2>/dev/null || echo "$cpu_sum")
        mem_sum=$((mem_sum + ${mem_samples[$i]}))
    done
    
    local cpu_avg=$(echo "scale=2; $cpu_sum / $count" | bc -l 2>/dev/null || echo "0")
    local mem_avg=$((mem_sum / count))
    local mem_mb=$((mem_avg / 1024))
    
    echo "    CPU: ${cpu_avg}%"
    echo "    Memory: ${mem_mb} MB (${mem_avg} KB)"
    echo ""
    
    echo "$label|$cpu_avg|$mem_mb" >> /tmp/zelynic-bench-results.txt
}

# Cleanup
$BINARY unstrict-all 2>/dev/null || true
rm -f /tmp/zelynic-bench-results.txt

# Test 1: No limit (baseline)
echo "Test 1: No limit (baseline)"
measure_overhead "no-limit" "$DURATION"

# Test 2: 1mb limit
echo "Test 2: 1mb limit"
$BINARY strict-single "$CURL_COMM" 1mb
sleep 2
measure_overhead "1mb-limit" "$DURATION"
$BINARY unstrict-all

# Test 3: 100kb limit (aggressive)
echo "Test 3: 100kb limit (aggressive)"
$BINARY strict-single "$CURL_COMM" 100kb
sleep 2
measure_overhead "100kb-limit" "$DURATION"
$BINARY unstrict-all

# Cleanup
kill "$CURL_PID" 2>/dev/null || true

# Summary
echo "━━━ Benchmark Summary ━━━"
echo ""
printf "%-15s %10s %10s\n" "TEST" "CPU%" "MEM(MB)"
printf "%-15s %10s %10s\n" "----" "----" "-------"
while IFS='|' read -r label cpu mem; do
    printf "%-15s %10s %10s\n" "$label" "$cpu" "$mem"
done < /tmp/zelynic-bench-results.txt

echo ""
echo "eBPF overhead is negligible if CPU < 1% and MEM < 10MB"

rm -f /tmp/zelynic-bench-results.txt
