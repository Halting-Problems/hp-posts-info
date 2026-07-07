#!/usr/bin/env python3
"""IOC scope scanner for shai_hulululud AI-scanner disruption package.

Searches repository trees and exported logs for literal IOC values associated with
shai_hulululud@1.0.48596 and its retrieved tarball artifact.

Exit codes:
  0: no matches
  1: one or more indicators matched
  2: execution error
"""

import argparse
import fnmatch
import json
import os
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT", "hp-shai-hulululud-ai-scanner-disruption-package-scope"))
URLS = ["https://registry.npmjs.org/shai_hulululud","https://registry.npmjs.org/shai_hulululud/-/shai_hulululud-1.0.48596.tgz"]
HASHES = ["9dcce285116e31a5c8f8e3a4ed596a791e62c3e47185e4ee36c489422b1fbbbc","8478bad8f0661d2a5ea65a8dc4bf86114f77d939"]
PACKAGE_VERSIONS = VERSIONS

# Collect unique indicators
indicators = set()
for group in [URLS, HASHES]:
    for val in group:
        if val:
            indicators.add(val)

PACKAGE_VERSIONS = ["shai_hulululud@1.0.48596"]
FILES = ["shai_hulululud-1.0.48596.tgz", "index.js"]
HASHES = [
    "9dcce285116e31a5c8f8e3a4ed596a791e62c3e47185e4ee36c489422b1fbbbc",
    "8478bad8f0661d2a5ea65a8dc4bf86114f77d939",
]
URLS = [
    "https://registry.npmjs.org/shai_hulululud",
    "https://registry.npmjs.org/shai_hulululud/-/shai_hulululud-1.0.48596.tgz",
    "https://socket.dev/blog/npm-package-uses-prompt-injection-and-token-flooding-to-disrupt-ai-malware-scanners",
]
PROCESS_PATTERNS = ["eval(", "shai_hulululud"]
CONTENT_INDICATORS = PACKAGES + PACKAGE_VERSIONS + FILES + HASHES + URLS + PROCESS_PATTERNS
PATH_INDICATORS = ["*shai_hulululud*", "*shai_hulululud-1.0.48596.tgz*"]
EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}


def _iter_files(root: str | Path):
    root = Path(root)
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            yield Path(current) / name


def _path_matches(path: Path) -> list[str]:
    text = str(path)
    matches: list[str] = []
    for indicator in PATH_INDICATORS:
        if indicator and (fnmatch.fnmatch(text, indicator) or fnmatch.fnmatch(path.name, indicator)):
            matches.append(indicator)
    return matches


def _content_matches(path: Path) -> list[str]:
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []
    return [indicator for indicator in CONTENT_INDICATORS if indicator and indicator in content]


def _scan_roots(roots: list[str]) -> list[str]:
    matches: list[str] = []
    for root in roots:
        if not root:
            continue
        for path in _iter_files(root):
            for indicator in _path_matches(path):
                matches.append(f"{path}: path matched {indicator!r}")
            for indicator in _content_matches(path):
                matches.append(f"{path}: content matched {indicator!r}")
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan files and logs for shai_hulululud IOC values")
    parser.add_argument("roots", nargs="*", default=["."], help="File or directory roots to scan")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log directory")
    parser.add_argument("--out", default=str(OUT), help="Output directory for scan artifacts")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    indicator_lines = sorted(set(CONTENT_INDICATORS + PATH_INDICATORS))
    (out_dir / "ioc-indicators.txt").write_text("\n".join(indicator_lines) + "\n", encoding="utf-8")

    roots = list(args.roots)
    if args.log_root:
        roots.append(args.log_root)
    matches = _scan_roots(roots)

    summary = {
        "roots": roots,
        "indicator_count": len(indicator_lines),
        "match_count": len(matches),
    }
    (out_dir / "scan-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if matches:
        (out_dir / "ioc-scope-matches.txt").write_text("\n".join(matches) + "\n", encoding="utf-8")
        print(f"[!] Found {len(matches)} IOC matches; summary written to {out_dir / 'scan-summary.json'}")
        return 1

    print(f"[+] No IOC matches found; summary written to {out_dir / 'scan-summary.json'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[-] Execution failure: {exc}", file=sys.stderr)
        sys.exit(2)
