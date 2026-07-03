#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Uninstall zelynic. Auto-detects installation location.
# Removes binary + BPF objects from all known locations.
#
# Usage:
#   ./scripts/uninstall.sh           → auto-detect + remove
#   sudo ./scripts/uninstall.sh      → can remove system-wide installs

set -euo pipefail

PROJECT_NAME="zelynic"
FOUND=false

# Check all common binary locations
for BINDIR in "/usr/bin" "/usr/local/bin" "${HOME}/.local/bin"; do
    BINARY="${BINDIR}/${PROJECT_NAME}"
    if [[ -f "${BINARY}" ]]; then
        if [[ -w "${BINDIR}" ]]; then
            rm -f "${BINARY}"
            echo "${PROJECT_NAME} removed from ${BINARY}"
            FOUND=true
        else
            echo "${PROJECT_NAME} found at ${BINARY} (requires sudo)"
            echo "  sudo rm -f ${BINARY}"
            FOUND=true
        fi
    fi
done

# Check all common BPF object locations
for BPFDIR in "/usr/lib/zelynic" "/usr/local/lib/zelynic" "${HOME}/.local/lib/zelynic"; do
    if [[ -d "${BPFDIR}" ]]; then
        if [[ -w "${BPFDIR}" ]]; then
            rm -rf "${BPFDIR}"
            echo "BPF objects removed from ${BPFDIR}/"
        else
            echo "BPF objects found at ${BPFDIR} (requires sudo)"
            echo "  sudo rm -rf ${BPFDIR}"
        fi
    fi
done

if ! $FOUND; then
    echo "${PROJECT_NAME} not found in any common location."
    echo "Checked: /usr/bin, /usr/local/bin, ~/.local/bin"
    exit 1
fi

echo "Uninstall complete."
