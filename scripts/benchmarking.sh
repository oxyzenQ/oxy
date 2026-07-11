#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for Python deep benchmarking engine.
# Bash for quick run, Python for beast — per project rules.
#
# Usage:
#   sudo ./scripts/benchmarking.sh                # full run
#   sudo ./scripts/benchmarking.sh --quick        # quick (3 iterations)
#   sudo ./scripts/benchmarking.sh --json         # machine-readable
#   sudo ./scripts/benchmarking.sh --stress 60    # 60s stress test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/benchmarking.py" "$@"
