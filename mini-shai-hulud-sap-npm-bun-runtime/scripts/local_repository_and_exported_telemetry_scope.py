#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
OUT = Path(os.environ.get('OUT', 'hp-mini-shai-hulud-sap-npm-bun-runtime-scope'))
OUT.mkdir(parents=True, exist_ok=True)

PACKAGES = ["mbt", "@cap-js/sqlite", "@cap-js/postgres", "@cap-js/db-service"]
PACKAGE_VERSIONS = ["mbt@1.2.48", "@cap-js/sqlite@2.2.2", "@cap-js/postgres@2.2.2", "@cap-js/db-service@2.10.1"]
FILES = ["setup.mjs", "execution.js", ".vscode/tasks.json", ".claude/settings.json", ".github/workflows/format-check.yml"]
HASHES = ["4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34", "80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac", "6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95"]
DOMAINS = ["api.github.com", "github.com", "registry.npmjs.org"]
URLS = ["https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/", "https://github.com/search?q=%22A+Mini+Shai-Hulud+has+Appeared%22&type=repositories"]
IPS = []
PROCESS_PATTERNS = ["Runner.Worker", "/proc/{pid}/mem", "node setup.mjs", "bun execution.js", "gh auth token"]
NETWORK_PATTERNS = ["A Mini Shai-Hulud has Appeared", "sardaukar-", "mentat-", "fremen-"]

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
