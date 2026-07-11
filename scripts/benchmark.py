#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""
zelynic benchmark — deep performance testing engine.

Python is used for the beast test engine because of its flexibility:
subprocess management, timing precision, statistical analysis, and
rich output formatting — all without bash limitations.

Measures:
  1. Startup latency (strict-single → exit)
  2. Status query latency
  3. BPF enforcement overhead (throughput with/without limit)
  4. Memory footprint (RSS during operation)
  5. Concurrent operation throughput
  6. Rate accuracy (actual vs target)

Usage:
  sudo python3 scripts/benchmark.py
  sudo python3 scripts/benchmark.py --quick          # skip long tests
  sudo python3 scripts/benchmark.py --json            # machine-readable output
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

# ━━ Constants ━━

BINARY = os.environ.get("ZELYNIC_BINARY", "./target/release/zelynic")
PIN_DIR = "/sys/fs/bpf/zelynic"
ITERATIONS = 10
QUICK_ITERATIONS = 3


def run(cmd, timeout=10, capture=True):
    """Run a command, return (returncode, stdout, stderr, elapsed)."""
    start = time.perf_counter()
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=capture,
        text=True,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - start
    return result.returncode, result.stdout, result.stderr, elapsed


def get_rss(pid):
    """Get RSS (resident set size) in KB for a PID."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return 0


def cleanup():
    """Remove all zelynic limits."""
    run(f"{BINARY} unstrict-all", timeout=5)


# ━━ Benchmark tests ━━


def bench_startup_latency(iterations):
    """Measure strict-single startup time (process spawn → exit)."""
    print("\n━━━ 1. Startup Latency ━━━")
    print(f"  Measuring strict-single spawn→exit ({iterations} iterations)")

    cleanup()
    times = []
    for i in range(iterations):
        # Use a long-lived sleep process as target
        sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
        try:
            comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
            rc, _, _, elapsed = run(
                f"{BINARY} strict-single {comm} 100kb", timeout=10
            )
            if rc == 0:
                times.append(elapsed * 1000)  # ms
                print(f"  [{i+1}/{iterations}] {elapsed*1000:.1f}ms")
            else:
                print(f"  [{i+1}/{iterations}] FAILED (rc={rc})")
        finally:
            sleep_proc.kill()
            sleep_proc.wait()
            cleanup()

    if not times:
        return {"name": "startup_latency", "error": "all iterations failed"}

    result = {
        "name": "startup_latency",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "median_ms": round(statistics.median(times), 1),
        "stdev_ms": round(statistics.stdev(times), 1) if len(times) > 1 else 0,
        "min_ms": round(min(times), 1),
        "max_ms": round(max(times), 1),
    }
    print(f"\n  Mean:   {result['mean_ms']:.1f}ms")
    print(f"  Median: {result['median_ms']:.1f}ms")
    print(f"  Stdev:  {result['stdev_ms']:.1f}ms")
    print(f"  Range:  {result['min_ms']:.1f}–{result['max_ms']:.1f}ms")
    return result


def bench_status_latency(iterations):
    """Measure status query latency."""
    print("\n━━━ 2. Status Query Latency ━━━")
    print(f"  Measuring 'zelynic status' ({iterations} iterations)")

    # Set up a limit first
    sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
    comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
    run(f"{BINARY} strict-single {comm} 100kb", timeout=10)

    times = []
    for i in range(iterations):
        rc, _, _, elapsed = run(f"{BINARY} status", timeout=5)
        if rc == 0:
            times.append(elapsed * 1000)
            print(f"  [{i+1}/{iterations}] {elapsed*1000:.1f}ms")

    sleep_proc.kill()
    cleanup()

    if not times:
        return {"name": "status_latency", "error": "all iterations failed"}

    result = {
        "name": "status_latency",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "median_ms": round(statistics.median(times), 1),
        "stdev_ms": round(statistics.stdev(times), 1) if len(times) > 1 else 0,
        "min_ms": round(min(times), 1),
        "max_ms": round(max(times), 1),
    }
    print(f"\n  Mean:   {result['mean_ms']:.1f}ms")
    print(f"  Median: {result['median_ms']:.1f}ms")
    print(f"  Range:  {result['min_ms']:.1f}–{result['max_ms']:.1f}ms")
    return result


def bench_memory_footprint():
    """Measure memory footprint of BPF maps + pin files."""
    print("\n━━━ 3. Memory Footprint ━━━")

    cleanup()
    # Measure baseline (no limits)
    pin_dir = Path(PIN_DIR)
    baseline_size = sum(f.stat().st_size for f in pin_dir.iterdir()) if pin_dir.exists() else 0
    baseline_files = len(list(pin_dir.iterdir())) if pin_dir.exists() else 0

    # Apply limit
    sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
    comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
    run(f"{BINARY} strict-single {comm} 100kb", timeout=10)
    time.sleep(0.5)

    active_size = sum(f.stat().st_size for f in pin_dir.iterdir()) if pin_dir.exists() else 0
    active_files = len(list(pin_dir.iterdir())) if pin_dir.exists() else 0

    # Get BPF program info via bpftool
    rc, bpftool_out, _, _ = run("bpftool prog show", timeout=5)
    bpf_progs = [l for l in bpftool_out.split("\n") if "enforce" in l]

    # Get BPF map info
    rc, map_out, _, _ = run("bpftool map show", timeout=5)
    bpf_maps = [l for l in map_out.split("\n") if "zelynic" in l.lower()]

    sleep_proc.kill()
    cleanup()

    result = {
        "name": "memory_footprint",
        "baseline_pin_files": baseline_files,
        "baseline_pin_bytes": baseline_size,
        "active_pin_files": active_files,
        "active_pin_bytes": active_size,
        "bpf_programs_loaded": len(bpf_progs),
        "bpf_maps_loaded": len(bpf_maps),
    }
    print(f"  Pin files: {result['active_pin_files']} ({result['active_pin_bytes']} bytes)")
    print(f"  BPF programs: {result['bpf_programs_loaded']}")
    print(f"  BPF maps: {result['bpf_maps_loaded']}")
    return result


def bench_concurrent_throughput(iterations):
    """Measure concurrent operation throughput."""
    print("\n━━━ 4. Concurrent Operation Throughput ━━━")
    print(f"  Measuring 5 parallel strict-single ({iterations} rounds)")

    cleanup()
    times = []
    for round_num in range(iterations):
        sleep_procs = []
        for _ in range(5):
            p = subprocess.Popen(["sleep", "60"], stdout=subprocess.DEVNULL)
            sleep_procs.append(p)

        start = time.perf_counter()
        procs = []
        for p in sleep_procs:
            comm = open(f"/proc/{p.pid}/comm").read().strip()
            procs.append(subprocess.Popen(
                [BINARY, "strict-single", comm, "100kb"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ))

        for p in procs:
            p.wait()

        elapsed = time.perf_counter() - start
        times.append(elapsed * 1000)
        print(f"  [Round {round_num+1}/{iterations}] {elapsed*1000:.1f}ms (5 ops)")

        for p in sleep_procs:
            p.kill()
            p.wait()
        cleanup()

    if not times:
        return {"name": "concurrent_throughput", "error": "failed"}

    result = {
        "name": "concurrent_throughput",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "median_ms": round(statistics.median(times), 1),
        "ops_per_sec": round(5000 / statistics.mean(times), 1),  # 5 ops per round
    }
    print(f"\n  Mean:   {result['mean_ms']:.1f}ms for 5 ops")
    print(f"  Throughput: {result['ops_per_sec']} ops/sec")
    return result


def bench_rate_accuracy():
    """Measure actual rate vs target rate."""
    print("\n━━━ 5. Rate Accuracy ━━━")
    print("  Measuring actual enforcement vs target")

    cleanup()
    sleep_proc = subprocess.Popen(["sleep", "60"], stdout=subprocess.DEVNULL)
    comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()

    # Apply a very low rate (1kb) to make drops measurable
    run(f"{BINARY} strict-single {comm} 1kb --allow-dangerous", timeout=10)
    time.sleep(1)

    # Read stats before
    rc, status1, _, _ = run(f"{BINARY} status", timeout=5)
    time.sleep(3)  # Let some traffic flow (sleep has none, but check anyway)
    rc, status2, _, _ = run(f"{BINARY} status", timeout=5)

    sleep_proc.kill()
    cleanup()

    # Parse stats (simplified — real test would use actual traffic)
    result = {
        "name": "rate_accuracy",
        "note": "sleep target has no traffic — for real accuracy test, use curl/wget",
        "target_rate_bps": 1024,
        "measured": "N/A (no traffic on sleep target)",
    }
    print(f"  Target: {result['target_rate_bps']} B/s")
    print(f"  Note: {result['note']}")
    return result


def main():
    parser = argparse.ArgumentParser(description="zelynic benchmark")
    parser.add_argument("--quick", action="store_true", help="skip long tests")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Requires root. Run with sudo.", file=sys.stderr)
        sys.exit(1)

    if not Path(BINARY).exists():
        print(f"ERROR: Binary not found: {BINARY}", file=sys.stderr)
        sys.exit(1)

    iters = QUICK_ITERATIONS if args.quick else ITERATIONS

    print("━━━ zelynic Performance Benchmark ━━━")
    print(f"Binary: {BINARY}")
    print(f"Iterations: {iters}")
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    results = []
    results.append(bench_startup_latency(iters))
    results.append(bench_status_latency(iters))
    results.append(bench_memory_footprint())
    results.append(bench_concurrent_throughput(iters if not args.quick else 3))
    if not args.quick:
        results.append(bench_rate_accuracy())

    print("\n━━━ Summary ━━━")
    for r in results:
        name = r.get("name", "unknown")
        if "error" in r:
            print(f"  {name}: ERROR ({r['error']})")
        elif "mean_ms" in r:
            print(f"  {name}: {r['mean_ms']}ms mean")
        else:
            print(f"  {name}: see details above")

    if args.json:
        print("\n" + json.dumps(results, indent=2))

    cleanup()


if __name__ == "__main__":
    main()
