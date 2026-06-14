#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-elementary-data-pypi-ghcr-compromise-scope"))
SINCE = "2026-04-24T22:10:00Z"
UNTIL = "2026-04-25T23:59:59Z"

PACKAGES = [
  "elementary-data",
]
VERSIONS = [
  "0.23.3",
  "elementary-data==0.23.3",
  "ghcr.io/elementary-data/elementary:0.23.3",
  "ghcr.io/elementary-data/elementary:latest",
]
FILES = [
  "elementary.pth",
  "trin.tar.gz",
  "/tmp/.trinny-security-update",
  "%TEMP%\\\\.trinny-security-update",
]
DOMAINS = [
  "igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud",
  "trin.tar.gz",
]
URLS = [
]
IPS = [
]
HASHES = [
  "sha256:31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255",
  "sha256:b3bbfafde1a0db3a4d47e70eb0eb2ca19daef4a19410154a71abee567b35d3d9",
  "sha256:fe52712660fef56586d954e50f81ccc7b96ed2809b5e930c7b9d032e7ab03b8d",
  "sha256:5cf8f4c3fa0b7e84cb0096c94eb9af941ea632c9acffa002d0db3b3c1d9ef97e",
  "31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255",
  "b3bbfafde1a0db3a4d47e70eb0eb2ca19daef4a19410154a71abee567b35d3d9",
  "fe52712660fef56586d954e50f81ccc7b96ed2809b5e930c7b9d032e7ab03b8d",
  "5cf8f4c3fa0b7e84cb0096c94eb9af941ea632c9acffa002d0db3b3c1d9ef97e",
]
PROCESS_PATTERNS = [
  "Python startup executes `elementary.pth`",
]
NETWORK_PATTERNS = [
  "egress related to elementary-data 0.23.3 package or GHCR image",
]

# Positive signal: repository, lockfile, artifact, process, or network telemetry contains one of the exact incident selectors above.
# Escalation: any match tied to a production build, CI run, deployed asset, or secret-bearing host moves the asset to presumed exposed.

OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "indicators.txt"

# Collect unique indicators
indicators = set()
for group in [PACKAGES, VERSIONS, FILES, DOMAINS, URLS, IPS, HASHES, PROCESS_PATTERNS, NETWORK_PATTERNS]:
    for val in group:
        if val:
            indicators.add(val)

with open(indicators_file, "w") as f:
    for ind in sorted(indicators):
        f.write(ind + "\n")

print(f"[+] Written unique selectors to {indicators_file}")

# Walk local directory
print(f"[+] Scanning directory: {ROOT} for selectors...")
matches = []
exclude_dirs = {"node_modules", "vendor", "dist", ".git"}
for root, dirs, filenames in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    for filename in filenames:
        filepath = Path(root) / filename
        try:
            content = filepath.read_text(errors="ignore")
            for ind in indicators:
                if ind in content:
                    matches.append(f"{filepath}: found '{ind}'")
        except Exception:
            pass

if matches:
    (OUT / "repository-indicator-matches.txt").write_text("\n".join(matches) + "\n")
    print(f"[!] Found {len(matches)} matches in codebase!")

# Optional Log Scanning
if LOG_ROOT and os.path.exists(LOG_ROOT):
    print(f"[+] Scanning telemetry log directory: {LOG_ROOT}...")
    log_matches = []
    for root, _, filenames in os.walk(LOG_ROOT):
        for filename in filenames:
            filepath = Path(root) / filename
            try:
                content = filepath.read_text(errors="ignore")
                for ind in indicators:
                    if ind in content:
                        log_matches.append(f"{filepath}: found '{ind}'")
            except Exception:
                pass
    if log_matches:
        (OUT / "exported-telemetry-indicator-matches.txt").write_text("\n".join(log_matches) + "\n")
        print(f"[!] Found {len(log_matches)} matches in logs!")

    if PACKAGES:
        registry_dir = OUT / "registry"
        registry_dir.mkdir(exist_ok=True)
        for package in PACKAGES:
            if not package: continue
            safe_name = package.replace("/", "__")
            print(f"[+] Querying pip index for {package}...")
            res = subprocess.run(["python3", "-m", "pip", "index", "versions", package], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"pypi-{safe_name}-versions.txt").write_text(res.stdout)
            subprocess.run(["python3", "-m", "pip", "download", "--no-deps", package, "-d", str(registry_dir)], capture_output=True)

print(f"[+] Wrote scope artifacts under {OUT}")
