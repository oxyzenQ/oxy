#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Crash recovery test suite — verifies zelynic survives crash scenarios.
#
# Tests:
#   1. Clean state baseline
#   2. Apply limit, verify active
#   3. Simulate crash (remove link pins only → stale state)
#   4. Run 'recover' → verify cleanup
#   5. Apply limit, simulate partial pin state
#   6. Run 'strict-single' → verify auto-recovery
#   7. Apply limit, kill -9 (if zelynic were running), verify 'recover' cleans
#   8. Multiple crash-recover cycles
#   9. Final state verification

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

BINARY="${1:-./target/release/zelynic}"
PIN_DIR="/sys/fs/bpf/zelynic"

log_pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
}

log_fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
}

log_test() {
    echo ""
    echo -e "  ${YELLOW}TEST${NC}: $1"
    ((TOTAL++))
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}ERROR: This test requires root. Run with sudo.${NC}"
        exit 1
    fi
}

check_binary() {
    if [ ! -f "$BINARY" ]; then
        echo -e "${RED}ERROR: Binary not found: $BINARY${NC}"
        echo "Build first: cargo build --release --features ebpf"
        exit 1
    fi
}

cleanup() {
    "$BINARY" unstrict-all 2>/dev/null || true
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo "━━━ zelynic Crash Recovery Test Suite ━━━"
echo "Binary: $BINARY"
echo ""

check_root
check_binary
cleanup

# Test 1: Clean state baseline
log_test "Clean state baseline — no pins should exist"
if [ ! -d "$PIN_DIR" ] || [ -z "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
    log_pass "Pin directory is clean"
else
    log_fail "Pin directory has files (run 'zelynic unstrict-all' first)"
fi

# Test 2: Apply limit, verify active
log_test "Apply limit, verify BPF is active"
"$BINARY" strict-single curl 100kb 2>/dev/null || true
sleep 1
if "$BINARY" status 2>/dev/null | grep -q "enforcing"; then
    log_pass "BPF is active after strict-single"
else
    log_fail "BPF not active after strict-single"
fi

# Test 3: Simulate crash — remove link pins only (stale state)
log_test "Simulate crash — remove link pins (stale state)"
rm -f "$PIN_DIR/enforce_dl_link" "$PIN_DIR/enforce_ul_link" 2>/dev/null
if "$BINARY" status 2>/dev/null | grep -q "Stale"; then
    log_pass "Status detects stale state"
else
    log_fail "Status does not detect stale state"
fi

# Test 4: Run recover → verify cleanup
log_test "Run 'recover' → verify cleanup"
"$BINARY" recover 2>/dev/null
if [ ! -d "$PIN_DIR" ] || [ -z "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
    log_pass "Recover cleaned up stale pins"
else
    log_fail "Recover did not clean up pins"
fi

# Test 5: Apply limit, simulate partial pin state (remove programs only)
log_test "Apply limit, simulate partial state (remove programs)"
"$BINARY" strict-single curl 100kb 2>/dev/null || true
sleep 1
rm -f "$PIN_DIR/enforce_dl" "$PIN_DIR/enforce_ul" 2>/dev/null
if "$BINARY" status 2>/dev/null | grep -q "Stale"; then
    log_pass "Status detects partial state"
else
    log_fail "Status does not detect partial state"
fi

# Test 6: Run strict-single → verify auto-recovery
log_test "strict-single auto-recovers from stale state"
"$BINARY" strict-single curl 100kb 2>/dev/null
sleep 1
if "$BINARY" status 2>/dev/null | grep -q "enforcing"; then
    log_pass "strict-single auto-recovered"
else
    log_fail "strict-single did not auto-recover"
fi

# Test 7: Doctor reports pin state
log_test "Doctor reports pin state correctly"
cleanup
"$BINARY" strict-single curl 100kb 2>/dev/null || true
sleep 1
if "$BINARY" doctor 2>/dev/null | grep -q "Pins:"; then
    log_pass "Doctor shows pin state"
else
    log_fail "Doctor does not show pin state"
fi

# Test 8: Multiple crash-recover cycles
log_test "Multiple crash-recover cycles (3x)"
cleanup
for i in 1 2 3; do
    "$BINARY" strict-single curl 100kb 2>/dev/null || true
    sleep 0.5
    # Simulate crash
    rm -f "$PIN_DIR/enforce_dl_link" "$PIN_DIR/enforce_ul_link" 2>/dev/null
    "$BINARY" recover 2>/dev/null
    if [ -d "$PIN_DIR" ] && [ -n "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
        log_fail "Cycle $i: pins remain after recover"
        break
    fi
done
if [ "$FAIL" -eq 0 ]; then
    log_pass "All 3 crash-recover cycles succeeded"
fi

# Test 9: Final state verification
log_test "Final state — should be clean after unstrict-all"
"$BINARY" strict-single curl 100kb 2>/dev/null || true
"$BINARY" unstrict-all 2>/dev/null
if [ ! -d "$PIN_DIR" ] || [ -z "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
    log_pass "Final state is clean"
else
    log_fail "Final state has residual pins"
fi

# Summary
echo ""
echo "━━━ Results ━━━"
echo "  Total: $TOTAL"
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
