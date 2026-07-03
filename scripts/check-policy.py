#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""Check Zelynic source policy rules."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
MAX_LOC = 1000
COPYRIGHT = "Copyright (C) 2026 rezky_nightky"
SPDX = "SPDX-License-Identifier: GPL-3.0-only"

CHECKED_SUFFIXES = {".rs", ".c", ".h", ".css", ".py", ".sh"}
EXCLUDED_DIRS = {
    ".git",
    "target",
    "assets",
    "dist",
    "release",
    "releases",
}
EXCLUDED_NAMES = {
    "Cargo.lock",
}
EXCLUDED_SUFFIXES = {
    ".md",
    ".txt",
}


def is_excluded(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in EXCLUDED_DIRS for part in relative.parts):
        return True
    if path.name in EXCLUDED_NAMES:
        return True
    if path.suffix in EXCLUDED_SUFFIXES:
        return True
    return False


def checked_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if is_excluded(path):
            continue
        if path.suffix in CHECKED_SUFFIXES:
            files.append(path)
    return sorted(files)


def header_window(lines: list[str]) -> list[str]:
    if lines and lines[0].startswith("#!"):
        return lines[1:6]
    return lines[:5]


def has_required_header(lines: list[str]) -> bool:
    window = header_window(lines)
    has_copyright = any(COPYRIGHT in line for line in window)
    has_spdx = any(SPDX in line for line in window)
    return has_copyright and has_spdx


def main() -> int:
    failures: list[str] = []
    files = checked_files()

    for path in files:
        relative = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()

        if len(lines) > MAX_LOC:
            failures.append(f"FAIL LOC    {relative}: {len(lines)} > {MAX_LOC}")

        if not has_required_header(lines):
            failures.append(f"FAIL HEADER {relative}: missing copyright/SPDX header")

    if failures:
        print("Zelynic policy check: FAIL")
        for failure in failures:
            print(failure)
        print(f"Checked {len(files)} file(s).")
        return 1

    print("Zelynic policy check: PASS")
    print(f"Checked {len(files)} file(s).")
    print(f"LOC limit: <= {MAX_LOC} for checked core/code files.")
    print("Headers: copyright + GPL-3.0-only SPDX present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
