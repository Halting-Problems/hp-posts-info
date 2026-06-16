#!/usr/bin/env python3
"""Scan a checkout or log export for Claude Code GitHub Action exposure indicators."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

INDICATORS = (
    {
        "id": "action_reference",
        "patterns": ("anthropics/claude-code", "uses: anthropics/claude-code"),
    },
    {
        "id": "version_boundary",
        "patterns": ("v2.1.128", "2.1.128"),
    },
    {
        "id": "workflow_secret",
        "patterns": ("ANTHROPIC_API_KEY",),
    },
    {
        "id": "readable_env_path",
        "patterns": ("/proc/self/environ",),
    },
)

SKIP_DIRS = {".git", ".venv", "__pycache__", "build", "dist", "node_modules", "vendor", "coverage"}
TEXT_SUFFIXES = {".txt", ".log", ".md", ".markdown", ".yml", ".yaml", ".json", ".js", ".ts", ".mdc"}
DEFAULT_OUT = "hp-claude-code-github-action-secret-exposure-scope"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=["."], help="Checkout or log export paths to scan")
    parser.add_argument("--json-out", type=Path, help="Optional path to write structured findings")
    return parser.parse_args()


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding, errors="ignore")
        except UnicodeDecodeError:
            continue
    return None


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    if not root.exists():
        return
    for child in root.rglob("*"):
        if child.is_dir():
            continue
        if any(part in SKIP_DIRS for part in child.parts):
            continue
        yield child


def scan_paths(paths: list[Path]):
    matches: list[dict[str, str]] = []
    for root in paths:
        for path in iter_files(root):
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"workflow", "action.yml", "action.yaml"}:
                continue
            text = read_text(path)
            if text is None:
                continue
            for indicator in INDICATORS:
                for pattern in indicator["patterns"]:
                    if pattern in text:
                        matches.append({"path": str(path), "indicator": indicator["id"], "pattern": pattern})
                        break
    return matches


def write_outputs(out_dir: Path, matches: list[dict[str, str]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    indicators_path = out_dir / "indicators.txt"
    indicators_path.write_text("\n".join(sorted({entry["indicator"] for entry in matches} or {item["id"] for item in INDICATORS})) + "\n", encoding="utf-8")
    if matches:
        (out_dir / "matches.json").write_text(json.dumps(matches, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    paths = [Path(p) for p in args.paths]
    matches = scan_paths(paths)
    out_dir = Path(args.json_out).parent if args.json_out else Path(DEFAULT_OUT)
    write_outputs(out_dir, matches)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps({"matches": matches}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"scanned={len(paths)} matches={len(matches)} out={out_dir}")
    return 1 if matches else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
