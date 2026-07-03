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

# Start a long-running background download
echo "Starting background download (curl 100MB)..."
curl -s -o /dev/null http://speedtest.tele2.net/100MB.zip &
CURL_PID=$!
CURL_COMM=$(cat /proc/$CURL_PID/comm 2>/dev/null || echo "curl")

# Wait for curl to start
sleep 2

# Verify curl is running
if ! kill -0 "$CURL_PID" 2>/dev/null; then
    echo "curl died, trying smaller file..."
    curl -s -o /dev/null http://speedtest.tele2.net/10MB.zip &
    CURL_PID=$!
    CURL_COMM=$(cat /proc/$CURL_PID/comm 2>/dev/null || echo "curl")
    sleep 1
fi

RESULTS_FILE="/tmp/zelynic-bench-results.txt"
rm -f "$RESULTS_FILE"

measure_overhead() {
    local label="$1"
    local duration="$2"
    
    echo "  Measuring: $label (${duration}s)..."
    
    local cpu_samples=()
    local mem_samples=()
    
    for i in $(seq 1 $((duration / 2))); do
        # Get zelynic serve child CPU + memory
        if [[ -f /tmp/zelynic.pid ]]; then
            local pid=$(cat /tmp/zelynic.pid)
            if kill -0 "$pid" 2>/dev/null; then
                local stats=$(ps -p "$pid" -o %cpu,%rss --no-headers 2>/dev/null || echo "0 0")
                local cpu=$(echo "$stats" | awk '{print $1}')
                local mem_kb=$(echo "$stats" | awk '{print $2}')
                cpu_samples+=("${cpu:-0}")
                mem_samples+=("${mem_kb:-0}")
            else
                cpu_samples+=("0")
                mem_samples+=("0")
            fi
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
    
    if [[ $count -eq 0 ]]; then
        count=1
    fi
    
    for i in "${!cpu_samples[@]}"; do
        cpu_sum=$(awk "BEGIN {print $cpu_sum + ${cpu_samples[$i]:-0}}")
        mem_sum=$((mem_sum + ${mem_samples[$i]:-0}))
    done
    
    local cpu_avg=$(awk "BEGIN {printf \"%.2f\", $cpu_sum / $count}")
    local mem_avg=$((mem_sum / count))
    local mem_mb=$((mem_avg / 1024))
    
    echo "    CPU: ${cpu_avg}%"
    echo "    Memory: ${mem_mb} MB (${mem_avg} KB)"
    echo ""
    
    echo "$label|$cpu_avg|$mem_mb" >> "$RESULTS_FILE"
}

# Cleanup any existing limits
$BINARY unstrict-all 2>/dev/null || true

# Test 1: No limit (baseline — measure curl overhead only)
echo "Test 1: No limit (baseline)"
measure_overhead "no-limit" "$DURATION"

# Test 2: 1mb limit
echo "Test 2: 1mb limit"
$BINARY strict-single "$CURL_COMM" 1mb 2>&1
sleep 3  # Wait for child to stabilize
measure_overhead "1mb-limit" "$DURATION"
$BINARY unstrict-all 2>/dev/null || true
sleep 1

# Test 3: 100kb limit (aggressive — more packet drops = more BPF work)
echo "Test 3: 100kb limit (aggressive)"
$BINARY strict-single "$CURL_COMM" 100kb 2>&1
sleep 3
measure_overhead "100kb-limit" "$DURATION"
$BINARY unstrict-all 2>/dev/null || true

# Cleanup
kill "$CURL_PID" 2>/dev/null || true

# Summary
echo "━━━ Benchmark Summary ━━━"
echo ""
printf "%-15s %10s %10s\n" "TEST" "CPU%" "MEM(MB)"
printf "%-15s %10s %10s\n" "----" "----" "-------"
while IFS='|' read -r label cpu mem; do
    printf "%-15s %10s %10s\n" "$label" "$cpu" "$mem"
done < "$RESULTS_FILE"

echo ""
echo "eBPF overhead is negligible if CPU < 1% and MEM < 10MB"
echo ""

# Check if serve child was alive during tests
if [[ "$(awk -F'|' '{print $2}' "$RESULTS_FILE" | awk '{s+=$1} END {print s}')" == "0" ]]; then
    echo "⚠ WARNING: All CPU readings were 0 — serve child may not have been running."
    echo "  Check: sudo zelynic -v strict-single curl 1mb"
    echo "  The setsid() fix should prevent child from dying on parent exit."
fi

rm -f "$RESULTS_FILE"
