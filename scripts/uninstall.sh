#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Uninstall zelynic: binary + BPF objects.
# Auto-detects and removes from:
#   binary:       /usr/bin/, ~/.local/bin/
#   BPF objects:  /usr/lib/zelynic/, ~/.local/lib/zelynic/
# Sudo is used ONLY for system paths. Run WITHOUT sudo.

set -uo pipefail

PROJECT_NAME="zelynic"
REPO_URL="https://github.com/oxyzenQ/zelynic"

usage() {
    cat <<EOF
Usage: $0 [--system|--user|--all]

  (default)  Auto-detect: scan /usr/bin, ~/.local/bin
             and remove every ${PROJECT_NAME} artifact found.
             Sudo only for system paths.
  --system   Remove only from /usr/bin and /usr/lib/${PROJECT_NAME} (uses sudo).
  --user     Remove only from ~/.local/bin and ~/.local/lib/${PROJECT_NAME} (no sudo).
  --all      Same as default.

Sudo is used only for system paths. Run WITHOUT sudo.
EOF
}

MODE="--all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --system) MODE="--system"; shift ;;
        --user)   MODE="--user";   shift ;;
        --all)    MODE="--all";    shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

SYSTEM_BIN="/usr/bin"
SYSTEM_BPF="/usr/lib/${PROJECT_NAME}"
USER_BIN="${HOME}/.local/bin"
USER_BPF="${HOME}/.local/lib/${PROJECT_NAME}"
removed=0

remove_at() {
    local target="$1"
    local need_sudo="$2"
    if [[ -e "${target}" ]]; then
        if [[ "${need_sudo}" == "yes" ]]; then
            sudo rm -rf "${target}"
        else
            rm -rf "${target}"
        fi
        echo "   removed: ${target}"
        removed=$((removed+1))
    fi
}

echo ">> Uninstalling ${PROJECT_NAME}"

case "${MODE}" in
    --system)
        remove_at "${SYSTEM_BIN}/${PROJECT_NAME}" yes
        remove_at "${SYSTEM_BPF}" yes
        ;;
    --user)
        remove_at "${USER_BIN}/${PROJECT_NAME}" no
        remove_at "${USER_BPF}" no
        ;;
    --all)
        remove_at "${SYSTEM_BIN}/${PROJECT_NAME}" yes
        remove_at "${SYSTEM_BPF}" yes
        remove_at "${USER_BIN}/${PROJECT_NAME}" no
        remove_at "${USER_BPF}" no
        ;;
esac

if [[ ${removed} -eq 0 ]]; then
    echo "   (nothing found to remove)"
    exit 0
fi

echo ">> Done. Removed ${removed} artifact(s)."
echo "  - Docs: ${REPO_URL}#readme"
