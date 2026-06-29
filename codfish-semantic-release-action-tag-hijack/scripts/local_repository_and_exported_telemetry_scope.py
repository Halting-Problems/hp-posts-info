#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").expanduser().resolve()
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-codfish-semantic-release-action-tag-hijack-scope"))

PACKAGES = ["codfish/semantic-release-action"]
HASHES = [
    "5792aba0e2180b9b80b77644370a6889d5817456",
    "8f9a58f2acdc190c356f79159b5de2548cdb63cd",
]
PACKAGE_VERSIONS = [
    "codfish/semantic-release-action@v5.0.0",
    "codfish/semantic-release-action@v5",
    "codfish/semantic-release-action@v4.0.1",
    "codfish/semantic-release-action@v4.0.0",
    "codfish/semantic-release-action@v4",
    "codfish/semantic-release-action@v3.5.0",
    "codfish/semantic-release-action@v3.4.1",
    "codfish/semantic-release-action@v3.4.0",
    "codfish/semantic-release-action@v3.3.0",
    "codfish/semantic-release-action@v3.2.0",
    "codfish/semantic-release-action@v3.1.1",
    "codfish/semantic-release-action@v3.1.0",
    "codfish/semantic-release-action@v3.0.0",
    "codfish/semantic-release-action@v3",
    "codfish/semantic-release-action@v2.2.1",
]
TEXT_SELECTORS = [
    'uses: "codfish/semantic-release-action@8f9a58f2acdc190c356f79159b5de2548cdb63cd"',
    "oven-sh/setup-bun",
    "bun run $GITHUB_ACTION_PATH/index.js",
    "using: composite",
]

VALIDATOR_REQUIRED_SELECTORS = [
    'action.yml',
    'Runner.Worker memory access',
    'https://raw.githubusercontent.com/codfish/semantic-release-action/5792aba0e2180b9b80b77644370a6889d5817456/action.yml',
    'https://raw.githubusercontent.com/codfish/semantic-release-action/8f9a58f2acdc190c356f79159b5de2548cdb63cd/action.yml',
]
INDICATOR_GROUPS = [PACKAGES, HASHES, PACKAGE_VERSIONS, TEXT_SELECTORS, VALIDATOR_REQUIRED_SELECTORS]

if not ROOT.exists():
    raise SystemExit(f"scan root does not exist: {ROOT}")

OUT.mkdir(parents=True, exist_ok=True)
indicators = set()
for group in INDICATOR_GROUPS:
    for value in group:
        indicators.add(value)

indicators_file = OUT / "indicators.txt"
indicators_file.write_text("\n".join(sorted(indicators)) + "\n", encoding="utf-8")
print(f"[+] Wrote selectors to {indicators_file}")


def scan_tree(base: Path) -> list[str]:
    matches: list[str] = []
    exclude_dirs = {".git", ".venv", "dist", "node_modules", "vendor", "coverage"}
    for current_root, dirs, files in os.walk(base):
        dirs[:] = [entry for entry in dirs if entry not in exclude_dirs]
        for filename in files:
            file_path = Path(current_root) / filename
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                raise RuntimeError(f"failed to read {file_path}: {exc}") from exc
            for indicator in indicators:
                if indicator in content:
                    matches.append(f"{file_path}: found '{indicator}'")
    return matches


repository_matches = scan_tree(ROOT)
if repository_matches:
    repository_file = OUT / "repository-indicator-matches.txt"
    repository_file.write_text("\n".join(repository_matches) + "\n", encoding="utf-8")
    print(f"[!] Found {len(repository_matches)} repository matches")
else:
    print("[+] No repository matches found")

if LOG_ROOT:
    log_base = Path(LOG_ROOT).expanduser().resolve()
    if log_base.exists():
        log_matches = scan_tree(log_base)
        if log_matches:
            log_file = OUT / "exported-telemetry-indicator-matches.txt"
            log_file.write_text("\n".join(log_matches) + "\n", encoding="utf-8")
            print(f"[!] Found {len(log_matches)} exported telemetry matches")
        else:
            print("[+] No exported telemetry matches found")
    else:
        raise SystemExit(f"LOG_ROOT does not exist: {log_base}")

print(f"[+] Scope artifacts written under {OUT}")
