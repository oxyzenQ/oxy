#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Long endurance test for zelynic.
# Runs continuous enforcement with periodic health checks.
#
# Usage: sudo ./scripts/long-endurance-test.sh [duration_hours]
# Default: 1 hour (use 24 for full 24-hour test)

set -euo pipefail

HOURS="${1:-1}"
DURATION_SEC=$((HOURS * 3600))
BINARY="${BINARY:-./target/release/zelynic}"
BPF_OBJ="bpf/limiter.bpf.o"
START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION_SEC))
CHECK_INTERVAL=300  # 5 minutes

if [[ $EUID -ne 0 ]]; then
    echo "Requires root. Run with sudo."
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    cargo build --release --features ebpf
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    if command -v clang >/dev/null 2>&1; then
        echo "Compiling BPF object..."
        clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o "$BPF_OBJ"
    else
        echo "BPF object not found. Using pre-compiled or skipping."
    fi
fi

echo "━━━ zelynic Long Endurance Test (${HOURS}h) ━━━"
echo "  Start: $(date)"
echo "  End:   $(date -d "@$END_TIME" 2>/dev/null || date -r "$END_TIME" 2>/dev/null || echo "N/A")"
echo "  Check interval: ${CHECK_INTERVAL}s"
echo ""

# Start background sleep process as target
sleep $DURATION_SEC &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")

# Apply limit
$BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
sleep 3

CHECK_COUNT=0
FAIL_COUNT=0

while [[ $(date +%s) -lt $END_TIME ]]; do
    CHECK_COUNT=$((CHECK_COUNT + 1))
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))
    ELAPSED_H=$((ELAPSED / 3600))
    ELAPSED_M=$(((ELAPSED % 3600) / 60))
    ELAPSED_S=$((ELAPSED % 60))

    # Health check
    STATUS=$($BINARY status 2>&1)

    if echo "$STATUS" | grep -q "Active limits"; then
        # Get stats
        ALLOWED=$(echo "$STATUS" | grep 'cg:' | head -1 | awk '{print $(NF-1)}' || echo "?")
        DROPPED=$(echo "$STATUS" | grep 'cg:' | head -1 | awk '{print $NF}' || echo "?")
        echo "  [${ELAPSED_H}h ${ELAPSED_M}m ${ELAPSED_S}s] ✓ Active | allowed=$ALLOWED dropped=$DROPPED"
    else
        echo "  [${ELAPSED_H}h ${ELAPSED_M}m ${ELAPSED_S}s] ✗ LIMIT LOST — re-applying..."
        $BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
        FAIL_COUNT=$((FAIL_COUNT + 1))
        sleep 3
    fi

    # Check for orphan maps every 10 checks
    if [[ $((CHECK_COUNT % 10)) -eq 0 ]]; then
        ORPHAN_PROGS=$(bpftool prog show 2>/dev/null | grep -c "enforce" || true)
        ORPHAN_PROGS=${ORPHAN_PROGS:-0}
        if [[ "$ORPHAN_PROGS" -gt 2 ]]; then
            echo "  ⚠ WARNING: $ORPHAN_PROGS BPF programs loaded (expected ≤2)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi

    # Check kernel log for errors every 20 checks
    if [[ $((CHECK_COUNT % 20)) -eq 0 ]]; then
        DMESG_ERRS=$(dmesg 2>/dev/null | tail -50 | grep -iE "bpf.*error|bpf.*fail|oops" || true)
        if [[ -n "$DMESG_ERRS" ]]; then
            echo "  ⚠ KERNEL LOG: BPF errors detected"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi

    sleep $CHECK_INTERVAL
done

# Cleanup
$BINARY unstrict-all 2>/dev/null || true
kill "$SLEEP_PID" 2>/dev/null || true

ELAPSED=$(( $(date +%s) - START_TIME ))
ELAPSED_H=$((ELAPSED / 3600))
ELAPSED_M=$(((ELAPSED % 3600) / 60))

echo ""
echo "━━━ Endurance Test Complete ━━━"
echo "  Duration: ${ELAPSED_H}h ${ELAPSED_M}m"
echo "  Checks: $CHECK_COUNT"
echo "  Failures: $FAIL_COUNT"
echo ""

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "  ✅ PASSED — zelynic stable for ${HOURS}h, zero failures"
    exit 0
else
    echo "  ❌ $FAIL_COUNT failure(s) during ${HOURS}h test"
    exit 1
fi
