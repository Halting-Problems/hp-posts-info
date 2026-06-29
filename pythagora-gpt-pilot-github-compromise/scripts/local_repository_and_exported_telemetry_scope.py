#!/usr/bin/env python3
"""Scan repository trees and exported logs for the Pythagora gpt-pilot compromise selectors."""


import os
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
LOG_ROOT = Path(os.environ["LOG_ROOT"]) if os.environ.get("LOG_ROOT") else None
OUT = Path(os.environ.get("OUT", "hp-pythagora-gpt-pilot-github-compromise-scope"))
INDICATORS_FILE = OUT / "indicators.txt"

FILES = [
    "_hooks.py",
    "_runtime.bin",
    "core/telemetry/_hooks.py",
    "core/telemetry/__init__.py",
]
HASHES = [
    "53154df1c66b42021f230c3fb6ef797c4b7c3e83",
    "90f59f5de6819a43ffe9b6272e3ed65aaadca804",
]
PROCESS_PATTERNS = [
    "Pythagora-io/gpt-pilot",
    "LeonOstrez",
    "ruff format --check",
    "ruff check",
    "E402",
    "I001",
    "No branch protection rules were configured on main",
]
NETWORK_PATTERNS = [
    "CI run #27133204878",
]


def build_indicators() -> list[str]:
    items: list[str] = []
    for group in (FILES, HASHES, PROCESS_PATTERNS, NETWORK_PATTERNS):
        items.extend(group)
    # Preserve order while removing duplicates.
    return list(dict.fromkeys([item for item in items if item]))


def iter_text_matches(base: Path, indicators: Iterable[str]) -> list[str]:
    matches: list[str] = []
    if not base.exists():
        return matches

    excluded = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", OUT.name}
    for root, dirs, filenames in os.walk(base):
        dirs[:] = [d for d in dirs if d not in excluded]
        for filename in filenames:
            path = Path(root) / filename
            try:
                content = path.read_text(errors="ignore")
            except Exception:
                continue
            for indicator in indicators:
                if indicator in content:
                    matches.append(f"{path}: found {indicator!r}")
    return list(dict.fromkeys(matches))


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    indicators = build_indicators()
    write_lines(INDICATORS_FILE, indicators)
    print(f"[+] Wrote {len(indicators)} indicators to {INDICATORS_FILE}")

    repo_matches = iter_text_matches(ROOT, indicators)
    if repo_matches:
        write_lines(OUT / "repository-indicator-matches.txt", repo_matches)
        print(f"[!] Found {len(repo_matches)} repository matches")
    else:
        print("[+] No repository matches")

    if LOG_ROOT is not None:
        log_matches = iter_text_matches(LOG_ROOT, indicators)
        if log_matches:
            write_lines(OUT / "exported-telemetry-indicator-matches.txt", log_matches)
            print(f"[!] Found {len(log_matches)} exported telemetry matches")
        else:
            print("[+] No exported telemetry matches")

    print(f"[+] Wrote scope artifacts under {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
