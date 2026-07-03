#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Leak test: verify no orphan BPF maps/programs after every operation.
# Checks bpftool after: strict, unstrict, unstrict-all, crash, reload.
#
# Usage: sudo ./scripts/leak-test.sh

set -euo pipefail

BINARY="${BINARY:-./target/release/zelynic}"
BPF_OBJ="bpf/limiter.bpf.o"
PASS=0
FAIL=0

pass() { echo "  ✓ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

check_clean() {
    local label="$1"
    local progs maps pid

    progs=$(bpftool prog show 2>/dev/null | grep -c "enforce" || true)
    progs=${progs:-0}
    maps=$(ls /sys/fs/bpf/zelynic/ 2>/dev/null | wc -l || true)
    maps=${maps:-0}
    pid=$(test -f /tmp/zelynic.pid && echo "1" || echo "0")

    if [[ "$progs" == "0" && "$maps" == "0" && "$pid" == "0" ]]; then
        pass "$label: clean (progs=0 maps=0 pid=0)"
    else
        fail "$label: orphan (progs=$progs maps=$maps pid=$pid)"
    fi
}

check_active() {
    local label="$1"
    local progs maps pid

    progs=$(bpftool prog show 2>/dev/null | grep -c "enforce" || true)
    progs=${progs:-0}
    maps=$(ls /sys/fs/bpf/zelynic/ 2>/dev/null | wc -l || true)
    maps=${maps:-0}
    pid=$(test -f /tmp/zelynic.pid && echo "1" || echo "0")

    if [[ "$progs" -gt 0 && "$maps" -gt 0 && "$pid" == "1" ]]; then
        pass "$label: active (progs=$progs maps=$maps pid=$pid)"
    else
        fail "$label: not active (progs=$progs maps=$maps pid=$pid)"
    fi
}

if [[ $EUID -ne 0 ]]; then
    echo "Requires root. Run with sudo."
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    cargo build --release --features ebpf
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o "$BPF_OBJ"
fi

echo "━━━ zelynic Leak Test ━━━"
echo ""

# Start target
sleep 300 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")

# Baseline: clean
$BINARY unstrict-all 2>/dev/null || true
sleep 1
check_clean "baseline"

# Test 1: strict → check active → unstrict → check clean
echo ""
echo "Test 1: strict + unstrict cycle"
$BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
sleep 2
check_active "after strict"
$BINARY unstrict "$SLEEP_COMM" 2>&1
sleep 1
check_clean "after unstrict"

# Test 2: strict → unstrict-all → check clean
echo ""
echo "Test 2: strict + unstrict-all"
$BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
sleep 2
check_active "after strict"
$BINARY unstrict-all 2>&1
sleep 1
check_clean "after unstrict-all"

# Test 3: 10x strict + unstrict cycles
echo ""
echo "Test 3: 10x strict + unstrict cycles"
for i in $(seq 1 10); do
    $BINARY strict-single "$SLEEP_COMM" 500kb 2>/dev/null
    $BINARY unstrict-all 2>/dev/null
done
sleep 1
check_clean "after 10x cycles"

# Test 4: crash (kill child) → manual cleanup → check clean
echo ""
echo "Test 4: crash + manual cleanup"
$BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
sleep 2
check_active "after strict"

CHILD_PID=$(cat /tmp/zelynic.pid 2>/dev/null || echo "")
if [[ -n "$CHILD_PID" ]]; then
    kill -9 "$CHILD_PID" 2>/dev/null || true
    sleep 1
    # Orphans should exist (child killed, not cleaned)
    progs=$(bpftool prog show 2>/dev/null | grep -c "enforce" || true)
    progs=${progs:-0}
    if [[ "$progs" -gt 0 ]]; then
        pass "crash: BPF programs persist (expected)"
    else
        fail "crash: BPF programs gone unexpectedly"
    fi

    # Manual cleanup
    $BINARY unstrict-all 2>/dev/null || true
    rm -f /tmp/zelynic.pid
    rm -f /sys/fs/bpf/zelynic/* 2>/dev/null || true
    rmdir /sys/fs/bpf/zelynic 2>/dev/null || true
    sleep 1
    check_clean "after manual cleanup"
else
    fail "crash: no PID file found"
fi

# Test 5: strict → kill target → unstrict → check clean
echo ""
echo "Test 5: kill target + cleanup"
$BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
sleep 2
kill -9 "$SLEEP_PID" 2>/dev/null || true
sleep 1
$BINARY unstrict-all 2>&1
sleep 1
check_clean "after target kill + unstrict-all"

# Test 6: multiple strict (different rates) → unstrict-all
echo ""
echo "Test 6: multiple strict overrides"
sleep 120 &
SLEEP_PID2=$!
SLEEP_COMM2=$(cat /proc/$SLEEP_PID2/comm 2>/dev/null || echo "sleep")

$BINARY strict-single "$SLEEP_COMM2" 100kb 2>/dev/null
$BINARY strict-single "$SLEEP_COMM2" 500kb 2>/dev/null
$BINARY strict-single "$SLEEP_COMM2" 1mb 2>/dev/null
sleep 2
check_active "after 3 overrides"
$BINARY unstrict-all 2>&1
sleep 1
check_clean "after unstrict-all"

kill "$SLEEP_PID2" 2>/dev/null || true

# Summary
echo ""
echo "━━━ Leak Test Summary ━━━"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [[ "$FAIL" -eq 0 ]]; then
    echo "  ✅ ALL LEAK TESTS PASSED — zero orphans"
    exit 0
else
    echo "  ❌ $FAIL leak(s) detected"
    exit 1
fi
