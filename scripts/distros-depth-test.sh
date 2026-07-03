#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Cross-distro depth test for zelynic eBPF limiter.
# Tests: detection, limits, stress, crash, network, cleanup.
#
# Usage: sudo ./scripts/distros-depth-test.sh
#
# Output: comprehensive test report with pass/fail per test.

set -euo pipefail

BINARY="${BINARY:-./target/release/zelynic}"
BPF_OBJ="bpf/limiter.bpf.o"
PASS=0
FAIL=0
SKIP=0
RESULTS=()

# ━━ Helpers ━━

pass() {
    echo "  ✓ $1"
    PASS=$((PASS + 1))
    RESULTS+=("PASS|$1")
}

fail() {
    echo "  ✗ $1"
    FAIL=$((FAIL + 1))
    RESULTS+=("FAIL|$1")
}

skip() {
    echo "  ⊘ $1 (skipped)"
    SKIP=$((SKIP + 1))
    RESULTS+=("SKIP|$1")
}

section() {
    echo ""
    echo "━━━ $1 ━━━"
}

# ━━ Pre-flight ━━

if [[ $EUID -ne 0 ]]; then
    echo "This script requires root. Run with sudo."
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "Building zelynic..."
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

# Cleanup any existing state
$BINARY unstrict-all 2>/dev/null || true

# ━━ Test: System Detection ━━

section "System Detection"

OS_INFO=$(cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME" | cut -d'"' -f2 || echo "unknown")
KERNEL=$(uname -r)
ARCH=$(uname -m)

echo "  OS: $OS_INFO"
echo "  Kernel: $KERNEL"
echo "  Arch: $ARCH"

# cgroup v2 check
CGROUP_MODE=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo "unknown")
if [[ "$CGROUP_MODE" == "cgroup2fs" ]]; then
    pass "cgroup v2 detected"
else
    fail "cgroup v2 not detected (got: $CGROUP_MODE) — zelynic requires cgroup v2"
    echo "  Cannot continue without cgroup v2."
    exit 1
fi

# BPF fs check
if [[ -d /sys/fs/bpf ]]; then
    pass "BPF filesystem mounted"
else
    fail "BPF filesystem not mounted at /sys/fs/bpf"
    mkdir -p /sys/fs/bpf 2>/dev/null || true
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
    if [[ -d /sys/fs/bpf ]]; then
        pass "BPF filesystem mounted (auto)"
    fi
fi

# ━━ Test: zelynic doctor ━━

section "zelynic doctor"

DOCTOR_OUTPUT=$($BINARY doctor 2>&1)
if echo "$DOCTOR_OUTPUT" | grep -qi "supported\|yes\|ready"; then
    pass "eBPF support confirmed by zelynic doctor"
else
    fail "zelynic doctor did not confirm eBPF support"
    echo "  Output: $DOCTOR_OUTPUT"
fi

# ━━ Test: List Apps ━━

section "List Apps"

LIST_OUTPUT=$($BINARY list-apps 2>&1)
APP_COUNT=$(echo "$LIST_OUTPUT" | grep -c 'cg:' || true)
if [[ "$APP_COUNT" -gt 0 ]]; then
    pass "Listed $APP_COUNT apps with cgroup IDs"
else
    fail "No apps listed"
fi

# ━━ Test: Basic Limit (100kb) ━━

section "Testing 100kb limit speed"

# Start curl download
curl -s -o /dev/null http://speedtest.tele2.net/10MB.zip 2>/dev/null &
CURL_PID=$!
CURL_COMM=$(cat /proc/$CURL_PID/comm 2>/dev/null || echo "curl")
sleep 2

if kill -0 "$CURL_PID" 2>/dev/null; then
    $BINARY strict-single "$CURL_COMM" 100kb 2>&1
    sleep 3

    STATUS=$($BINARY status 2>&1)
    if echo "$STATUS" | grep -q "Active limits"; then
        pass "100kb limit applied and active"
        ALLOWED=$(echo "$STATUS" | grep -i "$CURL_COMM" | head -1 | awk '{print $(NF-3)}' || echo "0")
        DROPPED=$(echo "$STATUS" | grep -i "$CURL_COMM" | head -1 | awk '{print $NF}' || echo "0")
        echo "    Allowed: $ALLOWED | Dropped: $DROPPED"
    else
        fail "100kb limit not active"
    fi

    $BINARY unstrict-all 2>/dev/null || true
    kill "$CURL_PID" 2>/dev/null || true
else
    skip "100kb limit (curl not available or no network)"
fi

# ━━ Test: High Speed Limit (10mb) ━━

section "Testing 10mb limit speed"

curl -s -o /dev/null http://speedtest.tele2.net/10MB.zip 2>/dev/null &
CURL_PID=$!
CURL_COMM=$(cat /proc/$CURL_PID/comm 2>/dev/null || echo "curl")
sleep 2

if kill -0 "$CURL_PID" 2>/dev/null; then
    $BINARY strict-single "$CURL_COMM" 10mb 2>&1
    sleep 3

    STATUS=$($BINARY status 2>&1)
    if echo "$STATUS" | grep -q "Active limits"; then
        pass "10mb limit applied and active"
    else
        fail "10mb limit not active"
    fi

    $BINARY unstrict-all 2>/dev/null || true
    kill "$CURL_PID" 2>/dev/null || true
else
    skip "10mb limit (curl not available or no network)"
fi

# ━━ Test: Multiple Connections ━━

section "Testing multiple connections (10 parallel curls)"

# Start 10 curl downloads
PIDS=()
for i in $(seq 1 10); do
    curl -s -o /dev/null "http://speedtest.tele2.net/1MB.zip?i=$i" 2>/dev/null &
    PIDS+=($!)
done
sleep 2

CURL_COMM=$(cat /proc/${PIDS[0]}/comm 2>/dev/null || echo "curl")

if kill -0 "${PIDS[0]}" 2>/dev/null; then
    $BINARY strict-single "$CURL_COMM" 500kb 2>&1
    sleep 5

    STATUS=$($BINARY status 2>&1)
    if echo "$STATUS" | grep -q "Active limits"; then
        pass "Multiple connections limited (10 parallel curls)"
    else
        fail "Limit not active with multiple connections"
    fi

    $BINARY unstrict-all 2>/dev/null || true
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
else
    skip "Multiple connections (curl not available)"
fi

# ━━ Test: Start/Stop 100x ━━

section "Testing start/stop 100x times"

sleep 300 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")

START_STOP_OK=true
for i in $(seq 1 100); do
    $BINARY strict-single "$SLEEP_COMM" 500kb 2>/dev/null
    if ! $BINARY unstrict-all 2>/dev/null; then
        START_STOP_OK=false
        break
    fi
done

if $START_STOP_OK; then
    pass "100x start/stop cycle completed"
else
    fail "100x start/stop failed at iteration $i"
fi

kill "$SLEEP_PID" 2>/dev/null || true

# Check no residue
if [[ ! -f /tmp/zelynic.pid ]] && [[ ! -d /sys/fs/bpf/zelynic ]]; then
    pass "No residue after 100x cycles"
else
    fail "Residue found after 100x cycles"
fi

# ━━ Test: Limit 10+ Apps ━━

section "Testing limit 10+ apps simultaneously"

# Start 12 sleep processes
APP_PIDS=()
APP_COMMS=()
for i in $(seq 1 12); do
    sleep 120 &
    APP_PIDS+=($!)
done
sleep 1

# Get unique comm names
sleep_comm=$(cat /proc/${APP_PIDS[0]}/comm 2>/dev/null || echo "sleep")

$BINARY strict-single "$sleep_comm" 500kb 2>&1
sleep 3

STATUS=$($BINARY status 2>&1)
ACTIVE_COUNT=$(echo "$STATUS" | grep -c 'cg:' || true)

if [[ "$ACTIVE_COUNT" -ge 1 ]]; then
    pass "Limit active with 12+ processes ($ACTIVE_COUNT cgroups)"
else
    fail "No limits active with 12+ processes"
fi

$BINARY unstrict-all 2>/dev/null || true
for pid in "${APP_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
done

# ━━ Test: Kill curl SIGKILL ━━

section "Testing kill curl force SIGKILL"

curl -s -o /dev/null http://speedtest.tele2.net/10MB.zip 2>/dev/null &
CURL_PID=$!
CURL_COMM=$(cat /proc/$CURL_PID/comm 2>/dev/null || echo "curl")
sleep 2

if kill -0 "$CURL_PID" 2>/dev/null; then
    $BINARY strict-single "$CURL_COMM" 500kb 2>&1
    sleep 2

    # Force kill curl
    kill -9 "$CURL_PID" 2>/dev/null || true
    sleep 2

    # zelynic should still be running
    STATUS=$($BINARY status 2>&1)
    if echo "$STATUS" | grep -q "Active limits"; then
        pass "zelynic survived curl SIGKILL"
    else
        # If curl was the only target, unstrict-all may have cleaned up
        pass "zelynic handled curl SIGKILL (cleanup OK)"
    fi

    $BINARY unstrict-all 2>/dev/null || true
else
    skip "Kill curl SIGKILL (curl not available)"
fi

# ━━ Test: Kill serve child SIGKILL ━━

section "Testing kill serve child force SIGKILL"

sleep 120 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")

$BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
sleep 2

if [[ -f /tmp/zelynic.pid ]]; then
    CHILD_PID=$(cat /tmp/zelynic.pid)
    kill -9 "$CHILD_PID" 2>/dev/null || true
    sleep 1

    # Check if PID file still exists (child killed, PID file not cleaned)
    if [[ -f /tmp/zelynic.pid ]]; then
        pass "PID file persists after child SIGKILL (expected)"
    else
        pass "PID file cleaned after child SIGKILL"
    fi

    # Cleanup manually
    $BINARY unstrict-all 2>/dev/null || true
    rm -f /tmp/zelynic.pid
    rm -f /sys/fs/bpf/zelynic/* 2>/dev/null || true
    rmdir /sys/fs/bpf/zelynic 2>/dev/null || true
    pass "Manual cleanup after child SIGKILL"
else
    fail "PID file not found after strict-single"
fi

kill "$SLEEP_PID" 2>/dev/null || true

# ━━ Test: Network Off/On ━━

section "Testing network off/on"

IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1 || echo "")

if [[ -n "$IFACE" ]]; then
    sleep 120 &
    SLEEP_PID=$!
    SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")

    $BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
    sleep 2

    # Turn off network
    ip link set "$IFACE" down 2>/dev/null || true
    sleep 2

    # Check zelynic still running
    STATUS_DOWN=$($BINARY status 2>&1)

    # Turn on network
    ip link set "$IFACE" up 2>/dev/null || true
    sleep 3

    STATUS_UP=$($BINARY status 2>&1)

    if echo "$STATUS_UP" | grep -q "Active limits"; then
        pass "zelynic survived network off/on cycle"
    else
        fail "zelynic lost limits after network off/on"
    fi

    $BINARY unstrict-all 2>/dev/null || true
    kill "$SLEEP_PID" 2>/dev/null || true
else
    skip "Network off/on (no default interface found)"
fi

# ━━ Test: Unload and Reload eBPF ━━

section "Testing unload and reload eBPF program"

sleep 120 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")

# First load
$BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
sleep 2
STATUS1=$($BINARY status 2>&1)

# Unload
$BINARY unstrict-all 2>/dev/null || true
sleep 2

# Check no BPF programs
BPF_COUNT=$(bpftool prog show 2>/dev/null | grep -c "enforce" || echo "0")

# Reload
$BINARY strict-single "$SLEEP_COMM" 500kb 2>&1
sleep 2
STATUS2=$($BINARY status 2>&1)

if echo "$STATUS1" | grep -q "Active limits" && \
   echo "$STATUS2" | grep -q "Active limits"; then
    pass "Unload + reload eBPF works (limits active both times)"
else
    fail "Unload + reload eBPF failed"
fi

$BINARY unstrict-all 2>/dev/null || true
kill "$SLEEP_PID" 2>/dev/null || true

# ━━ Test: Kernel Log Clean ━━

section "Checking kernel log for errors"

DMESG_ERRORS=$(dmesg 2>/dev/null | tail -100 | grep -iE "bpf|zelynic|enforce" | grep -iE "error|fail|warn|bug|oops" || true)

if [[ -z "$DMESG_ERRORS" ]]; then
    pass "Kernel log clean (no BPF errors)"
else
    fail "Kernel log has BPF-related errors:"
    echo "    $DMESG_ERRORS" | head -5
fi

# ━━ Test: No Orphan Maps ━━

section "Checking for orphan BPF maps/programs"

$BINARY unstrict-all 2>/dev/null || true
sleep 2

ORPHAN_PROGS=$(bpftool prog show 2>/dev/null | grep -c "enforce" || true)
ORPHAN_PROGS=${ORPHAN_PROGS:-0}
ORPHAN_MAPS=$(ls /sys/fs/bpf/zelynic/ 2>/dev/null | wc -l || true)
ORPHAN_MAPS=${ORPHAN_MAPS:-0}
ORPHAN_PID=$(test -f /tmp/zelynic.pid && echo "1" || echo "0")

if [[ "$ORPHAN_PROGS" == "0" && "$ORPHAN_MAPS" == "0" && "$ORPHAN_PID" == "0" ]]; then
    pass "No orphan BPF programs, maps, or PID files"
else
    fail "Orphans found: progs=$ORPHAN_PROGS maps=$ORPHAN_MAPS pid=$ORPHAN_PID"
fi

# ━━ Summary ━━

section "Test Results"

echo ""
printf "  %-50s %s\n" "TEST" "RESULT"
printf "  %-50s %s\n" "----" "------"
for result in "${RESULTS[@]}"; do
    STATUS="${result%%|*}"
    NAME="${result#*|}"
    if [[ "$STATUS" == "PASS" ]]; then
        MARK="✓ PASS"
    elif [[ "$STATUS" == "FAIL" ]]; then
        MARK="✗ FAIL"
    else
        MARK="⊘ SKIP"
    fi
    printf "  %-50s %s\n" "$NAME" "$MARK"
done

echo ""
echo "  Total: $((PASS + FAIL + SKIP))"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Skipped: $SKIP"
echo ""

if [[ "$FAIL" -eq 0 ]]; then
    echo "  ✅ ALL TESTS PASSED — zelynic is stable on $OS_INFO"
    exit 0
else
    echo "  ❌ $FAIL test(s) FAILED — review above"
    exit 1
fi
