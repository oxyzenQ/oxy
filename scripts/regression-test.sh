#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Regression test runner — runs all zelynic test suites in sequence.
#
# Usage:
#   sudo ./scripts/regression-test.sh           # run all
#   sudo ./scripts/regression-test.sh --quick   # skip endurance + stress
#
# Suites:
#   1. Unit tests (cargo test)
#   2. Crash recovery tests
#   3. Leak tests (orphan detection)
#   4. Stress tests (6-test suite)
#   5. Depth tests (17-test comprehensive suite)
#   6. Long endurance test (24h — skip with --quick)

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BINARY="${ZELYNIC_BINARY:-./target/release/zelynic}"
QUICK=false
PASS=0
FAIL=0

for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=true ;;
        -h|--help)
            echo "Usage: sudo $0 [--quick]"
            echo ""
            echo "  --quick  Skip endurance + stress tests (fast smoke test)"
            exit 0
            ;;
    esac
done

log_section() {
    echo ""
    echo -e "${CYAN}━━━ $1 ━━━${NC}"
}

log_pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    PASS=$((PASS + 1))
}

log_fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    FAIL=$((FAIL + 1))
}

run_suite() {
    local name="$1"
    local script="$2"
    local quick_skip="${3:-false}"

    if [ "$QUICK" = true ] && [ "$quick_skip" = true ]; then
        echo -e "  ${YELLOW}SKIP${NC}: $name (—quick mode)"
        return
    fi

    echo -e "  Running $name..."
    if bash "$script"; then
        log_pass "$name"
    else
        log_fail "$name"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo "━━━ zelynic Regression Test Suite ━━━"
echo "Binary: $BINARY"
echo "Mode: $([ "$QUICK" = true ] && echo "quick" || echo "full")"
echo "Date: $(date)"

# Check prerequisites
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: Requires root. Run with sudo.${NC}"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo -e "${RED}ERROR: Binary not found: $BINARY${NC}"
    echo "Build first: cargo build --release --features ebpf"
    exit 1
fi

# 1. Unit tests (no root needed, but run anyway)
log_section "1. Unit Tests (cargo test)"
if cargo test --features ebpf --locked 2>&1 | tail -5; then
    log_pass "cargo test"
else
    log_fail "cargo test"
fi

# 2. Crash recovery tests
log_section "2. Crash Recovery Tests"
run_suite "crash-recovery-test.sh" "scripts/crash-recovery-test.sh"

# 3. Leak tests
log_section "3. Leak Tests (Orphan Detection)"
run_suite "leak-test.sh" "scripts/leak-test.sh"

# 4. Stress tests
log_section "4. Stress Tests"
run_suite "stress-test.sh" "scripts/stress-test.sh" true

# 5. Depth tests
log_section "5. Depth Tests (Comprehensive)"
run_suite "distros-depth-test.sh" "scripts/distros-depth-test.sh"

# 6. Long endurance (skip in quick mode)
log_section "6. Long Endurance Test (24h)"
run_suite "long-endurance-test.sh" "scripts/long-endurance-test.sh" true

# Summary
log_section "Summary"
echo "  Suites passed: $PASS"
echo "  Suites failed: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}REGRESSION DETECTED${NC}"
    exit 1
fi

echo -e "${GREEN}ALL TESTS PASSED${NC}"
exit 0
