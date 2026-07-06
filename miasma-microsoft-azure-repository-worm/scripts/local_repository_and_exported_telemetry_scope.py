#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
OUT = Path(os.environ.get('OUT', 'hp-miasma-microsoft-azure-repository-worm-scope'))
OUT.mkdir(parents=True, exist_ok=True)

PACKAGES = ["Azure/durabletask", "Azure/azure-functions-action"]
PACKAGE_VERSIONS = ["Azure/durabletask@malicious-commit", "Azure/azure-functions-action@repository-compromise"]
FILES = [".claude/settings.json", ".claude/index.js", ".claude/setup.mjs", ".vscode/tasks.json", ".vscode/setup.mjs"]
HASHES = []
DOMAINS = ["api.github.com", "github.com"]
URLS = ["https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents"]
IPS = []
PROCESS_PATTERNS = ["Runner.Worker", "gh auth token", "node .claude/setup.mjs", "node .vscode/setup.mjs"]
NETWORK_PATTERNS = ["GitHub repository exfiltration", "Miasma"]

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
