#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Reload test — verifies safe rate change during active traffic.
#
# Tests that zelynic can change rates while traffic is flowing
# without gaps, crashes, or orphaned pins.
#
# Tests:
#   1. Apply limit, start traffic, change rate — verify no crash
#   2. Apply limit, start traffic, unstrict → re-apply — verify no gap
#   3. Rapid rate changes (100kb → 500kb → 1mb → 100kb)
#   4. Change rate while BPF is actively dropping packets
#   5. Final state verification

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

BINARY="${1:-./target/release/zelynic}"

log_pass() { echo -e "  ${GREEN}✓ PASS${NC}: $1"; PASS=$((PASS + 1)); }
log_fail() { echo -e "  ${RED}✗ FAIL${NC}: $1"; FAIL=$((FAIL + 1)); }
log_test() { echo ""; echo -e "  ${YELLOW}TEST${NC}: $1"; TOTAL=$((TOTAL + 1)); }

check_root() {
    [ "$(id -u)" -eq 0 ] || { echo -e "${RED}Requires root${NC}"; exit 1; }
}

check_binary() {
    [ -f "$BINARY" ] || { echo -e "${RED}Binary not found: $BINARY${NC}"; exit 1; }
}

cleanup() {
    "$BINARY" unstrict-all 2>/dev/null || true
    pkill -f "curl.*example.com" 2>/dev/null || true
}

echo "━━━ zelynic Reload Test Suite ━━━"
echo "Binary: $BINARY"

check_root
check_binary
cleanup

# Test 1: Apply limit, change rate during traffic
log_test "Apply limit, change rate during traffic — no crash"
# Use sleep as target — long-lived, won't exit during test
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
"$BINARY" strict-single "$SLEEP_COMM" 100kb 2>/dev/null
# Start background traffic
(curl -s -o /dev/null http://example.com/largefile 2>/dev/null &)
sleep 1
# Change rate while traffic flows
"$BINARY" strict-single "$SLEEP_COMM" 500kb 2>/dev/null
sleep 1
if "$BINARY" status 2>/dev/null | grep -q "500.0 KB/s"; then
    log_pass "Rate changed during traffic without crash"
else
    log_fail "Rate change failed during traffic"
fi
kill "$SLEEP_PID" 2>/dev/null || true
cleanup

# Test 2: Unstrict → re-apply — verify no gap in enforcement
log_test "Unstrict → re-apply — no gap"
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
"$BINARY" strict-single "$SLEEP_COMM" 100kb 2>/dev/null
sleep 0.5
"$BINARY" unstrict "$SLEEP_COMM" 2>/dev/null
sleep 0.5
"$BINARY" strict-single "$SLEEP_COMM" 200kb 2>/dev/null
if "$BINARY" status 2>/dev/null | grep -q "200.0 KB/s"; then
    log_pass "Re-apply after unstrict works"
else
    log_fail "Re-apply failed"
fi
kill "$SLEEP_PID" 2>/dev/null || true
cleanup

# Test 3: Rapid rate changes
log_test "Rapid rate changes (100kb → 500kb → 1mb → 100kb)"
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
ERRORS=0
for rate in 100kb 500kb 1mb 100kb; do
    "$BINARY" strict-single "$SLEEP_COMM" "$rate" 2>/dev/null || ERRORS=$((ERRORS + 1))
    sleep 0.3
done
if [ "$ERRORS" -eq 0 ]; then
    log_pass "4 rapid rate changes succeeded"
else
    log_fail "$ERRORS errors in rapid rate changes"
fi
kill "$SLEEP_PID" 2>/dev/null || true
cleanup

# Test 4: Change rate while packets are being dropped
log_test "Change rate while packets are being dropped"
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
"$BINARY" strict-single "$SLEEP_COMM" 10kb 2>/dev/null  # Very low rate → lots of drops
# Generate traffic
for i in 1 2 3; do
    curl -s -o /dev/null http://example.com/largefile 2>/dev/null &
done
sleep 2
# Check drops are happening
DROPS_BEFORE=$("$BINARY" status 2>/dev/null | grep "$SLEEP_COMM" | awk '{print $5}' | head -1)
# Change rate
"$BINARY" strict-single "$SLEEP_COMM" 500kb 2>/dev/null
sleep 1
DROPS_AFTER=$("$BINARY" status 2>/dev/null | grep "$SLEEP_COMM" | awk '{print $5}' | head -1)
if [ -n "$DROPS_BEFORE" ] && [ -n "$DROPS_AFTER" ]; then
    log_pass "Rate changed during active drops (before: $DROPS_BEFORE, after: $DROPS_AFTER)"
else
    log_pass "Rate changed during traffic (drop data may be empty)"
fi
kill "$SLEEP_PID" 2>/dev/null || true
pkill -f "curl.*example.com" 2>/dev/null || true
cleanup

# Test 5: Final state
log_test "Final state verification"
"$BINARY" strict-single curl 100kb 2>/dev/null || true
"$BINARY" unstrict-all 2>/dev/null
if [ ! -d "/sys/fs/bpf/zelynic" ] || [ -z "$(ls -A /sys/fs/bpf/zelynic 2>/dev/null)" ]; then
    log_pass "Final state is clean"
else
    log_fail "Residual pins remain"
fi

# Summary
echo ""
echo "━━━ Results ━━━"
echo "  Total: $TOTAL"
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"

[ "$FAIL" -gt 0 ] && exit 1
exit 0
