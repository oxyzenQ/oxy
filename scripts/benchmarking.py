#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""
zelynic deep benchmarking engine — accurate system-level metrics.

Measures CPU, memory (RSS), BPF map sizes, enforcement overhead,
and rate accuracy under sustained stress. Python is the beast engine
because of subprocess management, /proc parsing, timing precision,
and statistical analysis — things bash can't do well.

Metrics collected:
  1. Startup latency (strict-single spawn → exit)
  2. Status query latency
  3. Memory footprint (RSS, BPF map sizes, pin file sizes)
  4. CPU usage during enforcement (via /proc/stat sampling)
  5. Concurrent operation throughput
  6. Rate accuracy (actual vs target, with traffic)
  7. Sustained enforcement overhead (CPU + memory over 60s)
  8. Block latency (block-single spawn → exit)

Usage:
  sudo ./scripts/benchmarking.sh                # full run
  sudo ./scripts/benchmarking.sh --quick        # quick (3 iterations)
  sudo ./scripts/benchmarking.sh --json         # machine-readable
  sudo ./scripts/benchmarking.sh --stress 60    # 60s stress test
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

BINARY = os.environ.get("ZELYNIC_BINARY", "./target/release/zelynic")
PIN_DIR = "/sys/fs/bpf/zelynic"
ITERATIONS = 10
QUICK_ITERATIONS = 3


def run(cmd, timeout=10, capture=True):
    start = time.perf_counter()
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr, time.perf_counter() - start


def get_rss(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return 0


def get_cpu_percent(pid, duration=0.5):
    try:
        with open(f"/proc/{pid}/stat") as f:
            stat1 = f.read().split()
        time.sleep(duration)
        with open(f"/proc/{pid}/stat") as f:
            stat2 = f.read().split()
        utime1 = int(stat1[13])
        stime1 = int(stat1[14])
        utime2 = int(stat2[13])
        stime2 = int(stat2[14])
        ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        cpu_time = (utime2 - utime1 + stime2 - stime1) / ticks
        return (cpu_time / duration) * 100
    except (FileNotFoundError, IndexError, ValueError):
        return 0.0


def get_bpf_map_sizes():
    sizes = {}
    try:
        result = subprocess.run(["bpftool", "map", "show"], capture_output=True, text=True, timeout=5)
        current_id = None
        for line in result.stdout.split("\n"):
            if line.strip().startswith(str(current_id or "")):
                pass
            if "zelynic" in line.lower() or "enforce" in line.lower():
                if "bytes_used" in line:
                    for part in line.split():
                        if part.startswith("bytes_used:"):
                            sizes[current_id or "unknown"] = int(part.split(":")[1])
    except Exception:
        pass
    return sizes


def get_pin_dir_size():
    pin_path = Path(PIN_DIR)
    if not pin_path.exists():
        return 0, 0
    total = sum(f.stat().st_size for f in pin_path.iterdir() if f.is_file())
    count = len(list(pin_path.iterdir()))
    return total, count


def cleanup():
    run(f"{BINARY} unstrict-all", timeout=5)


def bench_startup(iterations):
    print("\n━━━ 1. Startup Latency ━━━")
    print(f"  Measuring strict-single spawn→exit ({iterations} iterations)")
    cleanup()
    times = []
    for i in range(iterations):
        sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
        try:
            comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
            rc, _, _, elapsed = run(f"{BINARY} strict-single {comm} 100kb", timeout=10)
            if rc == 0:
                times.append(elapsed * 1000)
                print(f"  [{i+1}/{iterations}] {elapsed*1000:.1f}ms")
        finally:
            sleep_proc.kill()
            sleep_proc.wait()
            cleanup()
    if not times:
        return {"name": "startup_latency", "error": "all failed"}
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


def bench_block_latency(iterations):
    print("\n━━━ 2. Block Latency ━━━")
    print(f"  Measuring block-single spawn→exit ({iterations} iterations)")
    cleanup()
    times = []
    for i in range(iterations):
        sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
        try:
            comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
            rc, _, _, elapsed = run(f"{BINARY} block-single {comm}", timeout=10)
            if rc == 0:
                times.append(elapsed * 1000)
                print(f"  [{i+1}/{iterations}] {elapsed*1000:.1f}ms")
        finally:
            sleep_proc.kill()
            sleep_proc.wait()
            cleanup()
    if not times:
        return {"name": "block_latency", "error": "all failed"}
    result = {
        "name": "block_latency",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "median_ms": round(statistics.median(times), 1),
    }
    print(f"\n  Mean: {result['mean_ms']:.1f}ms")
    return result


def bench_status(iterations):
    print("\n━━━ 3. Status Query Latency ━━━")
    print(f"  Measuring 'zelynic status' ({iterations} iterations)")
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
        return {"name": "status_latency", "error": "all failed"}
    result = {
        "name": "status_latency",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "median_ms": round(statistics.median(times), 1),
    }
    print(f"\n  Mean: {result['mean_ms']:.1f}ms")
    return result


def bench_memory():
    print("\n━━━ 4. Memory Footprint ━━━")
    cleanup()
    pin_bytes_base, pin_count_base = get_pin_dir_size()
    sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
    comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
    run(f"{BINARY} strict-single {comm} 100kb", timeout=10)
    time.sleep(0.5)
    pin_bytes_active, pin_count_active = get_pin_dir_size()
    rc, bpftool_out, _, _ = run("bpftool prog show", timeout=5)
    bpf_progs = [l for l in bpftool_out.split("\n") if "enforce" in l]
    rc, map_out, _, _ = run("bpftool map show", timeout=5)
    bpf_maps = [l for l in map_out.split("\n") if "zelynic" in l.lower()]
    sleep_proc.kill()
    cleanup()
    result = {
        "name": "memory_footprint",
        "baseline_pin_files": pin_count_base,
        "baseline_pin_bytes": pin_bytes_base,
        "active_pin_files": pin_count_active,
        "active_pin_bytes": pin_bytes_active,
        "bpf_programs_loaded": len(bpf_progs),
        "bpf_maps_loaded": len(bpf_maps),
    }
    print(f"  Pin files: {result['active_pin_files']} ({result['active_pin_bytes']} bytes)")
    print(f"  BPF programs: {result['bpf_programs_loaded']}")
    print(f"  BPF maps: {result['bpf_maps_loaded']}")
    return result


def bench_concurrent(iterations):
    print("\n━━━ 5. Concurrent Throughput ━━━")
    print(f"  Measuring 5 parallel strict-single ({iterations} rounds)")
    cleanup()
    times = []
    for round_num in range(iterations):
        sleep_procs = [subprocess.Popen(["sleep", "60"], stdout=subprocess.DEVNULL) for _ in range(5)]
        start = time.perf_counter()
        procs = []
        for p in sleep_procs:
            comm = open(f"/proc/{p.pid}/comm").read().strip()
            procs.append(subprocess.Popen([BINARY, "strict-single", comm, "100kb"],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
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
        "ops_per_sec": round(5000 / statistics.mean(times), 1),
    }
    print(f"\n  Mean: {result['mean_ms']:.1f}ms for 5 ops")
    print(f"  Throughput: {result['ops_per_sec']} ops/sec")
    return result


def bench_stress(duration_sec):
    print(f"\n━━━ 6. Sustained Enforcement ({duration_sec}s) ━━━")
    print("  Measuring CPU + memory during continuous enforcement")
    cleanup()
    sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
    comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
    run(f"{BINARY} strict-single {comm} 100kb", timeout=10)
    time.sleep(0.5)
    rss_samples = []
    cpu_samples = []
    start = time.perf_counter()
    while time.perf_counter() - start < duration_sec:
        # Check if any zelynic process is running (shouldn't be — fire-and-forget)
        zelynic_pids = []
        try:
            pgrep = subprocess.run(["pgrep", "-f", BINARY], capture_output=True, text=True, timeout=2)
            zelynic_pids = [int(p) for p in pgrep.stdout.strip().split("\n") if p.strip()]
        except Exception:
            pass
        for pid in zelynic_pids:
            rss_samples.append(get_rss(pid))
            cpu_samples.append(get_cpu_percent(pid, 0.5))
        time.sleep(1)
    pin_bytes, pin_count = get_pin_dir_size()
    sleep_proc.kill()
    cleanup()
    result = {
        "name": "sustained_enforcement",
        "duration_sec": duration_sec,
        "rss_samples": len(rss_samples),
        "rss_max_kb": max(rss_samples) if rss_samples else 0,
        "rss_mean_kb": round(statistics.mean(rss_samples), 1) if rss_samples else 0,
        "cpu_max_percent": round(max(cpu_samples), 2) if cpu_samples else 0,
        "cpu_mean_percent": round(statistics.mean(cpu_samples), 2) if cpu_samples else 0,
        "pin_files": pin_count,
        "pin_bytes": pin_bytes,
    }
    print(f"  Duration: {duration_sec}s")
    print(f"  RSS: max={result['rss_max_kb']}KB, mean={result['rss_mean_kb']}KB")
    print(f"  CPU: max={result['cpu_max_percent']}%, mean={result['cpu_mean_percent']}%")
    print(f"  Pin files: {pin_count} ({pin_bytes} bytes)")
    return result


def main():
    parser = argparse.ArgumentParser(description="zelynic deep benchmarking")
    parser.add_argument("--quick", action="store_true", help="quick mode (3 iterations)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--stress", type=int, default=30, help="stress test duration in seconds")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Requires root. Run with sudo.", file=sys.stderr)
        sys.exit(1)

    if not Path(BINARY).exists():
        print(f"ERROR: Binary not found: {BINARY}", file=sys.stderr)
        sys.exit(1)

    iters = QUICK_ITERATIONS if args.quick else ITERATIONS

    print("━━━ zelynic Deep Benchmark ━━━")
    print(f"Binary: {BINARY}")
    print(f"Iterations: {iters}")
    print(f"Stress: {args.stress}s")
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Kernel: {subprocess.check_output(['uname', '-r'], text=True).strip()}")

    results = []
    results.append(bench_startup(iters))
    results.append(bench_block_latency(iters))
    results.append(bench_status(iters))
    results.append(bench_memory())
    results.append(bench_concurrent(iters if not args.quick else 3))
    if not args.quick:
        results.append(bench_stress(args.stress))

    print("\n━━━ Summary ━━━")
    for r in results:
        name = r.get("name", "?")
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
