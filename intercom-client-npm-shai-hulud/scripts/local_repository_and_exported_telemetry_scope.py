#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-intercom-client-npm-shai-hulud-scope"))
SINCE = "2026-04-30T14:41:04Z"
UNTIL = "2026-06-08T11:53:00Z"

PACKAGES = [
  "intercom-client",
]
VERSIONS = [
  "7.0.4",
  "intercom-client@7.0.4",
]
FILES = [
  "setup.mjs",
  "router_runtime.js",
]
DOMAINS = [
  "api.github.com",
  "metadata.google.internal",
]
URLS = [
  "https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/",
]
IPS = [
  "169.254.169.254",
]
HASHES = [
  "5f748fbc89cde66abefa826439c765a0081a027792e9da8d80fbf23571311622",
  "fe64699649591948d6f960705caac86fe99600bf76e3eae29b4517705a58f0e2",
  "5ae8b2343e97cc3b2c945ec34318b63f27fa2db1e3d8fbaa78c298aa63db52ed",
]
PROCESS_PATTERNS = [
  "npm preinstall launches Bun-backed loader files",
]
NETWORK_PATTERNS = [
  "egress related to intercom-client 7.0.4",
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
            print(f"[+] Querying npm view for {package}...")
            res = subprocess.run(["npm", "view", package, "name", "version", "time", "versions", "dist-tags", "maintainers", "dist.tarball", "dist.integrity", "scripts", "--json"], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"npm-{safe_name}.json").write_text(res.stdout)

print(f"[+] Wrote scope artifacts under {OUT}")
