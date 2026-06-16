#!/usr/bin/env python3
"""Scan a checkout or exported log set for Claude Code GitHub Action exposure indicators.

The hunt focuses on the exact indicators reported in the case context:
- anthropics/claude-code
- v2.1.128
- ANTHROPIC_API_KEY
- /proc/self/environ

Exit codes:
  0 = no indicators found
  1 = at least one indicator matched
  2 = usage or read error
"""

import argparse
import json
import sys
from pathlib import Path
INDICATORS = (
    {
        "id": "action_reference",
        "category": "workflow",
        "patterns": ("anthropics/claude-code", "uses: anthropics/claude-code"),
    },
    {
        "id": "version_boundary",
        "category": "release",
        "patterns": ("v2.1.128", "2.1.128"),
    },
    {
        "id": "workflow_secret",
        "category": "secret",
        "patterns": ("ANTHROPIC_API_KEY",),
    },
    {
        "id": "readable_env_path",
        "category": "runtime",
        "patterns": ("/proc/self/environ",),
    },
)

SKIP_DIR_NAMES = {".git", ".venv", "__pycache__", "dist", "build", "node_modules", "vendor", "coverage"}
MAX_TEXT_BYTES = 2 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="One or more checkout or log-export paths to scan.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional path to write structured findings as JSON.",
    )
    return parser.parse_args()


def is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data:
        return False
    printable = sum(1 for byte in data[:4096] if byte in b"\t\n\r\x20" or 32 <= byte <= 126)
    return printable / min(len(data), 4096) >= 0.75


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None

    if len(data) > MAX_TEXT_BYTES:
        data = data[:MAX_TEXT_BYTES]

    if not is_probably_text(data):
        return None

    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding, errors="ignore")
        except UnicodeDecodeError:
            continue
    return None


def iter_candidate_files(target: Path):
    if target.is_file():
        yield target
        return

    if not target.exists():
        return

    for child in target.rglob("*"):
        if child.is_dir():
            continue
        if any(part in SKIP_DIR_NAMES for part in child.parts):
            continue
        yield child


def scan_text(text: str, file_path: Path):
    findings = []
    for indicator in INDICATORS:
        for pattern in indicator["patterns"]:
            start = 0
            while True:
                match_index = text.find(pattern, start)
                if match_index < 0:
                    break
                line_number = text.count("\n", 0, match_index) + 1
                line_start = text.rfind("\n", 0, match_index) + 1
                line_end = text.find("\n", match_index)
                if line_end < 0:
                    line_end = len(text)
                findings.append(
                    {
                        "category": indicator["category"],
                        "indicator_id": indicator["id"],
                        "pattern": pattern,
                        "file": str(file_path),
                        "line": line_number,
                        "excerpt": text[line_start:line_end].strip(),
                    }
                )
                start = match_index + len(pattern)
    return findings


def scan_path(target: Path):
    findings = []
    for candidate in iter_candidate_files(target):
        text = read_text(candidate)
        if text is None:
            continue
        findings.extend(scan_text(text, candidate))
    return findings


def main() -> int:
    args = parse_args()
    targets = [Path(path).expanduser().resolve() for path in args.paths]

    all_findings = []
    for target in targets:
        if not target.exists():
            print(f"[-] missing path: {target}", file=sys.stderr)
            return 2
        all_findings.extend(scan_path(target))

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(all_findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if all_findings:
        print(f"[!] matched {len(all_findings)} indicator occurrence(s)")
        for finding in all_findings:
            print(
                f"[MATCH] {finding['file']}:{finding['line']} "
                f"{finding['indicator_id']} => {finding['pattern']}"
            )
            print(f"        {finding['excerpt']}")
        return 1

    print("[+] no Claude Code GitHub Action exposure indicators found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
