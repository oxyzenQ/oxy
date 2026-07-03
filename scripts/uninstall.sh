#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Uninstall zelynic. Auto-detects installation location.
# Checks: /usr/bin, /usr/local/bin, ~/.local/bin
#
# Usage:
#   ./scripts/uninstall.sh           → auto-detect + remove
#   sudo ./scripts/uninstall.sh      → can remove system-wide installs

set -euo pipefail

PROJECT_NAME="zelynic"
FOUND=false

# Check all common install locations
for BINDIR in "/usr/bin" "/usr/local/bin" "${HOME}/.local/bin"; do
    BINARY="${BINDIR}/${PROJECT_NAME}"
    if [[ -f "${BINARY}" ]]; then
        # Check if we have permission to remove
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

if ! $FOUND; then
    echo "${PROJECT_NAME} not found in any common location."
    echo "Checked: /usr/bin, /usr/local/bin, ~/.local/bin"
    exit 1
fi

echo "Uninstall complete."
