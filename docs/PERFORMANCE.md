# Performance Metrics

> Baseline performance targets + measurement methodology for zelynic v7.0.0+.

## Measurement Methodology

Performance is measured using `scripts/benchmark.py` — a Python-based
deep performance testing engine. Python is used (instead of bash) for:
- Precise timing (`time.perf_counter()`)
- Statistical analysis (mean, median, stdev, percentiles)
- Subprocess management
- Rich output formatting

Run the benchmark:
```bash
sudo python3 scripts/benchmark.py           # full (10 iterations)
sudo python3 scripts/benchmark.py --quick   # quick (3 iterations)
sudo python3 scripts/benchmark.py --json    # machine-readable output
```

## Baseline Targets

> Measured on: Arch Linux (CachyOS), kernel 6.18.38, AMD Ryzen 7 5800HS, 3 iterations (--quick mode)

### Startup Latency

| Operation | Target | Measured |
|-----------|--------|----------|
| `strict-single` (spawn → exit) | < 50ms | **32.3ms** ✅ |
| `unstrict-all` | < 30ms | TBD |
| `recover` (stale state) | < 50ms | TBD |

### Query Latency

| Operation | Target | Measured |
|-----------|--------|----------|
| `status` (1 limit) | < 20ms | **10.7ms** ✅ |
| `status` (50 limits) | < 100ms | TBD |
| `list-apps` | < 100ms | TBD |

### Memory Footprint

| Component | Target | Measured |
|-----------|--------|----------|
| Pin files (13 files) | < 10KB | **0 bytes** ✅ |
| BPF programs (2) | kernel-managed | **2 programs** ✅ |
| BPF maps (8) | < 100KB total | 8 pinned (bpftool counts differ) |
| Userspace RSS (during op) | < 5MB | process exits after apply |

### Throughput

| Operation | Target | Measured |
|-----------|--------|----------|
| Concurrent strict-single (5 parallel) | < 200ms total | **31.3ms** ✅ |
| Rate change during traffic | < 50ms | TBD |
| Throughput (ops/sec) | > 50 | **159.6 ops/sec** ✅ |

### Rate Accuracy

| Target Rate | Actual Rate | Error | Status |
|-------------|-------------|-------|--------|
| 100 KB/s | TBD | < 0.1% | TBD |
| 1 MB/s | TBD | < 0.1% | TBD |
| 10 MB/s | TBD | < 0.1% | TBD |

## Optimization History

### v7.0.0 — Lazy Identity Refresh

**Before**: `open_pinned()` always refreshed identity map (scans /proc for
all cgroups). This added ~50-100ms to every write operation.

**After**: Identity refresh is lazy — only triggered by `status` command
(which needs it for display). Write operations (`strict-single`, `unstrict`)
skip identity refresh entirely.

**Impact**: Write operations ~50-100ms faster. Status unaffected.

## BPF Instruction Budget

The BPF verifier has a 1-million instruction limit per program. zelynic's
`enforce_dl` + `enforce_ul` programs are well under this limit:

| Program | Instructions | Verifier Complexity | Status |
|---------|-------------|---------------------|--------|
| `enforce_dl` | TBD | TBD | Verified ✅ |
| `enforce_ul` | TBD | TBD | Verified ✅ |

Check with:
```bash
sudo bpftool prog show | grep enforce
sudo bpftool prog profile id <ID> duration 10
```

## Methodology Notes

1. **Warm-up**: First iteration is discarded (cold cache effects)
2. **Isolation**: Tests run on idle system (no other CPU-intensive tasks)
3. **Consistency**: Each test runs N iterations, reports mean + stdev
4. **Cleanup**: Each test cleans up BPF state before exiting
5. **Root**: All tests require root (BPF operations)

## Regression Detection

Run the benchmark before + after any performance-sensitive change:

```bash
sudo python3 scripts/benchmark.py --json > before.json
# ... make changes ...
sudo python3 scripts/benchmark.py --json > after.json
diff <(jq -S . before.json) <(jq -S . after.json)
```

If mean latency increases by > 10%, investigate the regression.
