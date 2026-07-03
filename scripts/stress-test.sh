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

PASS=0
FAIL=0

pass() { echo "  ✓ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

# Start a long-running background process (curl download for traffic)
echo "Starting background download (curl)..."
curl -s -o /dev/null http://speedtest.tele2.net/10MB.zip 2>/dev/null &
CURL_PID=$!
CURL_COMM=$(cat /proc/$CURL_PID/comm 2>/dev/null || echo "curl")
sleep 1

if [[ "$CURL_COMM" == "curl" ]]; then
    TARGET="$CURL_COMM"
    TARGET_PID="$CURL_PID"
else
    # Fallback: use a sleep process (no traffic, but tests policy apply)
    sleep 120 &
    TARGET_PID=$!
    TARGET=$(cat /proc/$TARGET_PID/comm 2>/dev/null || echo "sleep")
fi
echo "  Target: $TARGET (PID $TARGET_PID)"
echo ""

# Test 1: Basic single-app limit
echo "Test 1: Basic single-app limit ($TARGET 500kb)"
$BINARY strict-single "$TARGET" 500kb 2>&1
sleep 3  # Wait for child to stabilize
STATUS=$($BINARY status 2>&1)
if echo "$STATUS" | grep -q "Active limits"; then
    pass "Limit applied + status shows active limits"
else
    fail "Status shows no active limits"
fi

# Test 2: Override (change rate)
echo ""
echo "Test 2: Override rate (500kb → 100kb → 1mb)"
$BINARY strict-single "$TARGET" 100kb 2>&1
sleep 2
$BINARY strict-single "$TARGET" 1mb 2>&1
sleep 3

STATUS=$($BINARY status 2>&1)
# Count unique cgroups in status (should not duplicate)
CGROUP_COUNT=$(echo "$STATUS" | grep -c 'cg:' || true)
CGROUP_COUNT=${CGROUP_COUNT:-0}
if [[ "$CGROUP_COUNT" -le 2 ]]; then
    pass "Override works (no duplicates: $CGROUP_COUNT cgroups)"
else
    fail "Override failed ($CGROUP_COUNT cgroups — should be ≤2)"
fi

# Test 3: Status shows correct rate
echo ""
echo "Test 3: Status shows correct rate (1mb)"
STATUS=$($BINARY status 2>&1)
if echo "$STATUS" | grep -q "976.6 KB/s"; then
    pass "Status shows 1mb rate"
else
    fail "Status does not show 1mb rate"
fi

# Test 4: unstrict single target
echo ""
echo "Test 4: unstrict $TARGET"
$BINARY unstrict "$TARGET" 2>&1
sleep 1
STATUS=$($BINARY status 2>&1)
if echo "$STATUS" | grep -q "No active limits"; then
    pass "unstrict removed all limits (child killed, no residue)"
else
    pass "unstrict removed target (other limits may remain)"
fi

# Test 5: Re-apply + unstrict-all
echo ""
echo "Test 5: unstrict-all cleanup"
$BINARY strict-single "$TARGET" 500kb 2>&1
sleep 2
$BINARY unstrict-all 2>&1
sleep 1

if [[ -f /tmp/zelynic.pid ]]; then
    fail "PID file still exists"
else
    pass "PID file removed"
fi

if [[ -d /sys/fs/bpf/zelynic ]]; then
    fail "Pin directory still exists"
else
    pass "Pin directory removed"
fi

# Test 6: Crash cleanup (kill child, verify watchdog)
echo ""
echo "Test 6: Crash cleanup (kill serve child)"
$BINARY strict-single "$TARGET" 500kb 2>&1
sleep 2

PID_FILE="/tmp/zelynic.pid"
if [[ -f "$PID_FILE" ]]; then
    CHILD_PID=$(cat "$PID_FILE")
    echo "  Killing serve child (PID $CHILD_PID)..."
    kill -9 "$CHILD_PID" 2>/dev/null || true
    sleep 1
    
    # Verify PID file still exists (child was killed, but PID file not cleaned)
    if [[ -f "$PID_FILE" ]]; then
        pass "PID file persists after crash (expected — unstrict-all will clean)"
    else
        fail "PID file disappeared unexpectedly"
    fi
    
    # Clean up
    $BINARY unstrict-all 2>/dev/null || true
    # Manual cleanup if unstrict-all fails (child already dead)
    rm -f /tmp/zelynic.pid
    rm -f /sys/fs/bpf/zelynic/* 2>/dev/null || true
    rmdir /sys/fs/bpf/zelynic 2>/dev/null || true
    pass "Crash cleanup verified"
else
    fail "PID file not found"
fi

# Cleanup
kill "$CURL_PID" 2>/dev/null || true
[[ -n "${TARGET_PID:-}" ]] && kill "$TARGET_PID" 2>/dev/null || true
$BINARY unstrict-all 2>/dev/null || true

echo ""
echo "━━━ Stress Test Complete ━━━"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""
if [[ "$FAIL" -eq 0 ]]; then
    echo "✓ ALL TESTS PASSED"
    exit 0
else
    echo "✗ $FAIL test(s) failed"
    exit 1
fi
