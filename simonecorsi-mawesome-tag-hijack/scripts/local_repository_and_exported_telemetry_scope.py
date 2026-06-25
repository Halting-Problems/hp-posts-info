#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").expanduser().resolve()
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-simonecorsi-mawesome-tag-hijack-scope"))

PACKAGES = ["simonecorsi/mawesome"]
HASHES = [
    "e339407b8e34dc1540290d1d310bccafbc6028ca",
    "4a665037e0619e2181c7cccc3291d75104175a92",
    "6e26314c306ed5ea744eb90ebc6f3f70298abcb5",
    "7a59a7d02b1fdf6432ea9467b8e31357217288f7",
]
PACKAGE_VERSIONS = [
    "simonecorsi/mawesome@latest",
    "simonecorsi/mawesome@v1",
    "simonecorsi/mawesome@v2",
    "simonecorsi/mawesome@v2.2.0",
]
TEXT_SELECTORS = [
    'uses: "simonecorsi/mawesome@4a665037e0619e2181c7cccc3291d75104175a92"',
    'uses: "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"',
    "bun run $GITHUB_ACTION_PATH/index.js",
    "using: composite",
    "createCipheriv",
    "createDecipheriv",
    "pbkdf2Sync",
    "VAULT_TOKEN",
    "ARM_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "X-GitHub-Api-Version",
]
INDICATOR_GROUPS = [PACKAGES, HASHES, PACKAGE_VERSIONS, TEXT_SELECTORS]

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
    exclude_dirs = {".git", ".venv", "dist", "node_modules", "vendor", "coverage", OUT.name}
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
        print(f"[!] LOG_ROOT does not exist: {log_base}")
