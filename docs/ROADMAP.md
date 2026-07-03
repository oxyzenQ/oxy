# zelynic Roadmap

> Future direction after v4.0.0 stable release.

## v4.0.0 (Current — Wolf Architecture)

**Status**: v4.0.0-alpha, pending cross-distro testing

- ✅ Pure eBPF enforcement (no tc/nft/systemd-wrapper)
- ✅ Per-app rate limiting (download + upload)
- ✅ Group limiting (strict-multi shared token bucket)
- ✅ Fire-and-forget (child process + pinned maps)
- ✅ Watchdog (30s auto-disable safety)
- ✅ Audit log (JSONL)
- ✅ 17/17 depth tests pass (Arch Linux, kernel 6.18)
- ⬜ Cross-distro testing (Ubuntu, Fedora, Debian)
- ⬜ Kernel 5.13/6.1/6.6 LTS testing
- ⬜ 24h endurance test
- ⬜ Stable release

## v4.1.0 — Polish + Edge Cases

- [ ] `--json` output for all commands (scripting integration)
- [ ] `--cgroup <id>` filter for observer
- [ ] `--min-bytes <N>` filter for observer
- [ ] Orphan policy cleanup (cgroup dies, policy auto-removed)
- [ ] Signal handling: SIGTERM → graceful unstrict-all
- [ ] Config file (~/.config/zelynic/config.toml)
- [ ] Profile support (shell aliases → native profiles)

## v4.2.0 — Performance Optimization

- [ ] Per-CPU stats maps (BPF_MAP_TYPE_PERCPU_HASH) — eliminate atomic contention
- [ ] Batch map operations (BPF_MAP_LOOKUP_AND_DELETE_BATCH)
- [ ] Cache-aligned BPF map values (#[repr(align(64))])
- [ ] Timerfd-based enforcement loop (replace 200ms sleep)
- [ ] Map pre-allocation (avoid runtime BPF_MAP_UPDATE_ELEM)

## v5.0.0 — Advanced Features

- [ ] Ingress observer (cgroup_skb/ingress counter — currently limiter only)
- [ ] DSCP marking via sock_ops (QoS priority)
- [ ] XDP ingress counter (pre-cgroup, interface-level)
- [ ] Per-process enforcement (not just per-cgroup) via bpf_get_current_pid_tgid
- [ ] Persistent policies via BPF map pinning at /sys/fs/bpf/zelynic/
- [ ] systemd unit file for auto-apply on boot
- [ ] TUI dashboard (optional, behind feature flag)

## v6.0.0 — Ecosystem

- [ ] AUR package (zelynic, zelynic-bin)
- [ ] RPM package (Fedora)
- [ ] Debian package
- [ ] Docker image (for CI/testing)
- [ ] Python binding (libzelynic.so)
- [ ] REST API (optional, behind feature flag)

## Non-Goals (Forever)

- Windows support
- macOS/BSD eBPF support
- Daemon mode (serve child is minimal, not a daemon)
- tc/nft/systemd-wrapper fallback (legacy stays on `main` branch)
- REST API as default (CLI-first always)

## Release Cadence

- **v4.x**: monthly minor releases (bug fixes + small features)
- **v5.x**: quarterly major releases (new BPF hooks, advanced features)
- **v6.x**: yearly major releases (ecosystem, packaging)

## Compatibility Promise

- v4.x: kernel 5.13+, cgroup v2, root required
- v5.x: may bump to kernel 6.1+ LTS (for new BPF features)
- v6.x: may bump to kernel 6.6+ LTS

Legacy v3.x (tc/nft) stays on `main` branch indefinitely for users who
need it. No forced migration.
