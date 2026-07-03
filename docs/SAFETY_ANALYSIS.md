# Safety Analysis

> Is zelynic safe? Is it malware? What happens when it crashes?

## Short Answer

**zelynic is safe. It is not malware.** It is a pure eBPF bandwidth limiter
that:
- Does NOT collect, transmit, or store user data
- Does NOT make network connections (except `--check-update` which is opt-in)
- Does NOT modify system files (except `/sys/fs/bpf/zelynic/` pin files)
- Does NOT install services, cron jobs, or daemons
- Does NOT require internet access to function
- Fails SAFE: on any error, BPF allows all traffic (no blocking on failure)

## What zelynic Does

### BPF Programs (kernel)
- Hooks `cgroup_skb/ingress` and `cgroup_skb/egress` on cgroup v2 root
- Counts packets per cgroup (observer)
- Enforces token-bucket rate limits per cgroup (limiter)
- **Returns 1 (allow)** on every error path — never blocks on failure

### Userspace (Rust binary)
- Loads BPF programs via aya
- Reads/writes BPF maps (policies, stats, watchdog)
- Walks `/proc` to resolve process names → cgroup IDs
- Refreshes watchdog every 200ms (serve child only)
- Pins maps to `/sys/fs/bpf/zelynic/` for fire-and-forget access

### What zelynic Does NOT Do
- ❌ No telemetry, analytics, or phone-home
- ❌ No automatic network connections (except opt-in `--check-update`)
- ❌ No data collection or logging of user activity
- ❌ No modification of system files (except BPF pin files)
- ❌ No installation of systemd services or cron jobs
- ❌ No background daemon (serve child is minimal: sleeps + refreshes watchdog)
- ❌ No reading of user files (only `/proc/*/comm` and `/proc/*/cgroup`)
- ❌ No network packet inspection (BPF only counts bytes, doesn't read content)

## File System Access

| Path | Read/Write | Purpose |
|------|------------|---------|
| `/proc/*/comm` | Read | Process name for target resolution |
| `/proc/*/cgroup` | Read | Cgroup path for target resolution |
| `/proc/*/status` | Read | UID for identity display |
| `/sys/fs/cgroup/*` | Read | `cgroup.id` file for ID resolution |
| `/sys/fs/cgroup` | Read | Attach BPF programs |
| `/sys/fs/bpf/zelynic/*` | Read/Write | Pinned BPF maps |
| `/tmp/zelynic.pid` | Read/Write | Serve child PID tracking |
| `~/.local/share/zelynic/audit.jsonl` | Write | Audit log (enforcement events) |

**No other file system access.** No reading of user documents, browser data,
network config, or system passwords.

## Network Access

zelynic makes **zero outbound network connections** during normal operation.

The only network-related activity:
1. **BPF programs**: hook network packets in kernel (count/enforce) — do NOT
   read packet content, do NOT connect to anything
2. **`--check-update` flag**: opt-in GitHub API call to check latest release.
   Disabled by default. Only runs when user explicitly requests it.

## Crash Safety

### If zelynic crashes (serve child dies):
1. Watchdog deadline stops being refreshed
2. After 30 seconds, BPF program sees `now > deadline` → returns 1 (allow all)
3. All traffic resumes automatically — no manual intervention needed
4. No residue: PID file + pin files remain, but BPF is no-op

### If user runs `unstrict-all`:
1. Serve child killed (SIGTERM → wait 3s → SIGKILL)
2. PID file removed
3. Pin files removed (`/sys/fs/bpf/zelynic/*`)
4. Pin directory removed
5. BPF programs unloaded (kernel cleans up when last reference closes)
6. **Zero residue** — system returns to pre-zelynic state

### If user reboots:
1. Serve child dies (part of normal shutdown)
2. PID file remains (in `/tmp`, cleared on reboot)
3. Pin files remain (in `/sys/fs/bpf`, cleared on reboot since bpffs is tmpfs)
4. BPF programs unloaded
5. **Zero residue** after reboot

## BPF Safety

### Verifier guarantees:
- **No infinite loops**: BPF verifier guarantees program termination
- **No out-of-bounds access**: all memory accesses bounds-checked
- **No unbounded resource consumption**: maps have fixed max_entries
- **No kernel crash**: BPF runs in sandbox, cannot crash kernel (Linux 5.x+)

### Fail-safe design:
- No policy for cgroup → allow (return 1)
- Rate = 0 → allow (return 1)
- Bucket creation fails → allow (return 1)
- Map lookup fails → allow (return 1)
- Watchdog expired → allow (return 1)
- Watchdog not set → allow (return 1) — **but only in ephemeral mode**

### Pin mode (fire-and-forget):
- Watchdog is set to 0 (disabled) — BPF always enforces
- If serve child crashes: watchdog stays at 0, BPF keeps enforcing
- Recovery: `zelynic unstrict-all` kills child + removes pins
- If `unstrict-all` fails (child already dead): manual cleanup with `rm`

## Memory Safety (Rust)

zelynic is written in Rust, which provides:
- **Memory safety**: no buffer overflows, no use-after-free, no null dereferences
- **Thread safety**: no data races (Rust ownership model)
- **No unsafe code** in userspace (except `libc::clock_gettime` and `libc::setsid`,
  both standard POSIX calls with well-defined semantics)

### BPF C code:
- BPF verifier ensures memory safety at load time
- All map accesses bounds-checked by verifier
- No dynamic allocation (BPF programs can't allocate memory)

## Race Conditions

### BPF map access:
- BPF maps are kernel-managed, atomic operations
- Multiple CPUs can access maps concurrently — kernel handles synchronization
- `stats->packets += 1` is NOT atomic, but this is acceptable:
  - Under-counting is possible (lost updates)
  - Over-counting is not possible
  - Stats are for display only, not for enforcement decisions

### Watchdog refresh:
- Serve child refreshes every 200ms
- BPF reads deadline atomically (single u64 read)
- If refresh is late, BPF may briefly allow all traffic (safe direction)

### Parent + child map access:
- Both access pinned maps via separate file descriptors
- Kernel BPF map operations are atomic per-entry
- `insert` (write policy) and `remove` (delete policy) are atomic
- No torn reads/writes possible

## Audit Log

zelynic logs enforcement events to `~/.local/share/zelynic/audit.jsonl`:
- `enforce_start`: when strict command is run
- `policy_apply`: which cgroup + rate was applied
- `enforce_stop`: when unstrict is run
- `rate_rejected`: when a rate below minimum is rejected

**This log is local only.** It is never transmitted anywhere. It contains:
- Timestamps
- Cgroup IDs + process names
- Rate limits (bytes/second)
- Packet counts (allowed/dropped)

**No packet content, no URLs, no IP addresses, no user data.**

## Verifying Safety Yourself

### Check network connections:
```bash
# While zelynic is running, check for any network connections
sudo ss -tunp | grep zelynic
# Should show nothing (except --check-update if running)
```

### Check file access:
```bash
# Trace file access by zelynic
sudo strace -f -e trace=openat zelynic strict-single brave 100kb 2>&1 | head -50
```

### Check BPF programs:
```bash
# See what BPF programs are loaded
sudo bpftool prog show | grep -A2 enforce
```

### Check BPF maps:
```bash
# See what BPF maps are pinned
ls -la /sys/fs/bpf/zelynic/
```

### Check for residue after unstrict-all:
```bash
sudo zelynic unstrict-all
ls /sys/fs/bpf/zelynic/ 2>&1  # should not exist
ls /tmp/zelynic.pid 2>&1      # should not exist
sudo bpftool prog show | grep enforce  # should be empty
```

## License

GPL-3.0-only — source code is fully open. Anyone can audit, modify, and
verify every line of code.

## Conclusion

zelynic is safe, non-malicious, and fails in the safe direction (allow all
traffic on any error). It does not collect data, make network connections,
or modify system files beyond BPF pin files. The source code is open for
full audit under GPL-3.0-only.
