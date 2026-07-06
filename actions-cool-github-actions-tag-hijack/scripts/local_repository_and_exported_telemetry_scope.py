#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
OUT = Path(os.environ.get('OUT', 'hp-actions-cool-github-actions-tag-hijack-scope'))
OUT.mkdir(parents=True, exist_ok=True)

PACKAGES = ["actions-cool/issues-helper", "actions-cool/maintain-one-comment"]
PACKAGE_VERSIONS = ["actions-cool/issues-helper@mutable-tags", "actions-cool/maintain-one-comment@mutable-tags"]
FILES = ["action.yml", "dist/index.js", "/home/runner/.bun/bin/bun"]
HASHES = ["1c9e803c80cc7fed000022d4c94f4b5bc2e90062"]
DOMAINS = ["t.m-kosche.com"]
URLS = ["https://app.stepsecurity.io/github/actions-security-demo/compromised-packages/actions/runs/26056902433"]
IPS = []
PROCESS_PATTERNS = ["Runner.Worker", "/proc/<Runner.Worker PID>/mem", "gh auth token", "sudo python3", "isSecret"]
NETWORK_PATTERNS = ["HTTPS to t.m-kosche.com"]

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return f"__READ_ERROR__:{path}:{exc}"

def scan_tree(base: Path, indicators: set[str]) -> list[str]:
    matches = []
    skip = {".git", "node_modules", "vendor", "dist", ".venv", "__pycache__"}
    for current_root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            path = Path(current_root) / name
            text = read_text(path)
            for indicator in indicators:
                if indicator and indicator in text:
                    matches.append(f"{path}: found {indicator!r}")
    return matches

indicators = set()
for group in [PACKAGES, PACKAGE_VERSIONS, FILES, HASHES, DOMAINS, URLS, IPS, PROCESS_PATTERNS, NETWORK_PATTERNS]:
    indicators.update(group)

(OUT / "indicators.txt").write_text("\n".join(sorted(indicators)) + "\n", encoding="utf-8")
matches = scan_tree(ROOT, indicators)
(OUT / "matches.txt").write_text("\n".join(matches) + ("\n" if matches else ""), encoding="utf-8")
print(f"[+] wrote {len(indicators)} selectors and {len(matches)} matches under {OUT}")
