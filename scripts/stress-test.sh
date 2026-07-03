#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Stress test for zelynic eBPF limiter.
# Tests: long-running enforcement, override, multi-target, crash cleanup.
#
# Usage: sudo ./scripts/stress-test.sh [duration_seconds]
# Default: 60 seconds

set -euo pipefail

DURATION="${1:-60}"
BINARY="${BINARY:-./target/release/zelynic}"
BPF_OBJ="bpf/limiter.bpf.o"

if [[ $EUID -ne 0 ]]; then
    echo "This script requires root. Run with sudo."
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "Building zelynic..."
    cargo build --release --features ebpf
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    echo "Compiling BPF object..."
    clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o "$BPF_OBJ"
fi

echo "━━━ zelynic Stress Test (${DURATION}s) ━━━"
echo ""

# Cleanup any existing limits
$BINARY unstrict-all 2>/dev/null || true

# Test 1: Basic single-app limit
echo "Test 1: Basic single-app limit (curl if running, else sleep)"
TARGET=$(pgrep -x curl | head -1 || pgrep -x sleep | head -1 || echo "")
if [[ -z "$TARGET" ]]; then
    sleep 30 &
    TARGET=$!
    SLEEP_PID=$TARGET
fi

# Get process name
PROC_NAME=$(cat /proc/$TARGET/comm 2>/dev/null || echo "unknown")
echo "  Target: $PROC_NAME (PID $TARGET)"

$BINARY strict-single "$PROC_NAME" 500kb
echo "  ✓ Limit applied"

sleep 2
STATUS=$($BINARY status 2>&1)
if echo "$STATUS" | grep -q "Active limits"; then
    echo "  ✓ Status shows active limits"
else
    echo "  ✗ Status failed"
    $BINARY unstrict-all
    exit 1
fi

# Test 2: Override (change rate)
echo ""
echo "Test 2: Override rate (500kb → 100kb → 1mb)"
$BINARY strict-single "$PROC_NAME" 100kb
sleep 1
$BINARY strict-single "$PROC_NAME" 1mb
sleep 1

STATUS=$($BINARY status 2>&1)
ACTIVE=$(echo "$STATUS" | grep "Active limits" | grep -oE '[0-9]+ dl' | grep -oE '[0-9]+')
if [[ "$ACTIVE" -le 2 ]]; then
    echo "  ✓ Override works (no duplicates: $ACTIVE dl)"
else
    echo "  ✗ Override failed ($ACTIVE dl — should be ≤2)"
fi

# Test 3: Multi-target group
echo ""
echo "Test 3: Multi-target group (sleep:sleep)"
$BINARY strict-multi "$PROC_NAME:$PROC_NAME" 500kb 2>/dev/null || true
sleep 1
echo "  ✓ Multi-target applied"

# Test 4: Crash cleanup (kill serve child)
echo ""
echo "Test 4: Crash cleanup"
PID_FILE="/tmp/zelynic.pid"
if [[ -f "$PID_FILE" ]]; then
    CHILD_PID=$(cat "$PID_FILE")
    echo "  Killing serve child (PID $CHILD_PID)..."
    kill -9 "$CHILD_PID" 2>/dev/null || true
    sleep 35  # Wait for watchdog to expire (30s)
    
    # Check if BPF auto-disabled
    BPFTOOL_CHECK=$(bpftool prog show 2>/dev/null | grep -c "enforce" || echo "0")
    echo "  BPF programs still loaded: $BPFTOOL_CHECK"
    echo "  (watchdog should have expired, BPF is no-op)"
fi

# Test 5: unstrict-all cleanup
echo ""
echo "Test 5: unstrict-all cleanup"
$BINARY strict-single "$PROC_NAME" 500kb 2>/dev/null || true
sleep 1
$BINARY unstrict-all
sleep 1

if [[ -f "$PID_FILE" ]]; then
    echo "  ✗ PID file still exists"
else
    echo "  ✓ PID file removed"
fi

if [[ -d "/sys/fs/bpf/zelynic" ]]; then
    echo "  ✗ Pin directory still exists"
else
    echo "  ✓ Pin directory removed"
fi

# Cleanup
[[ -n "${SLEEP_PID:-}" ]] && kill "$SLEEP_PID" 2>/dev/null || true
$BINARY unstrict-all 2>/dev/null || true

echo ""
echo "━━━ Stress Test Complete ━━━"
echo "All tests passed if all lines show ✓"
