#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-mini-shai-hulud-worm-scope"))
SINCE = "2026-04-20T00:00:00Z"
UNTIL = "2026-05-23T23:59:59Z"

PACKAGES = [
  "@tanstack/react-router",
  "@tanstack/vue-router",
  "@tanstack/solid-router",
  "@tanstack/react-start",
  "@tanstack/router-core",
  "@antv/g2",
  "@antv/g6",
  "@antv/x6",
  "@antv/l7",
  "@antv/s2",
  "@antv/f2",
  "echarts-for-react",
  "timeago.js",
  "size-sensor",
  "canvas-nest.js",
  "@sap/cds",
  "@sap/cds-dk",
  "opensearch-py",
  "lite-llm",
  "nx-console",
]
VERSIONS = [
  "@tanstack/react-router@1.169.5",
  "@tanstack/react-router@1.169.8",
  "@tanstack/vue-router@1.169.5",
  "@tanstack/vue-router@1.169.8",
  "@tanstack/solid-router@1.169.5",
  "@tanstack/solid-router@1.169.8",
  "@tanstack/react-start@1.167.68",
  "@tanstack/react-start@1.167.71",
  "@antv/g2@4.2.8",
  "@antv/g6@4.8.24",
  "nx-console@18.95.0",
  "@antv/* published 2026-05-19T01:39:00",
]
FILES = [
  "router_init.js",
  "setup_bun.js",
  "bun_environment.js",
  "transformers.pyz",
  "gh-token-monitor",
]
DOMAINS = [
  "filev2.getsession.org",
  "api.masscan.cloud",
  "git-tanstack.com",
  "t.m-kosche.com",
  "www.endorlabs.com",
  "www.microsoft.com",
  "www.sentinelone.com",
]
URLS = [
  "https://filev2.getsession.org/upload",
  "https://api.masscan.cloud/ping",
  "https://www.endorlabs.com/blog/mini-shai-hulud-npm-worm-hits-sap-developer-packages",
  "https://tanstack.com/blog/postmortem-cve-2026-45321",
  "https://www.microsoft.com/en-us/security/blog/hunting-the-shai-hulud-supply-chain-worm",
  "https://www.sentinelone.com/blog/anatomy-of-cve-2026-45321",
]
IPS = [
]
HASHES = [
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
]
PROCESS_PATTERNS = [
]
NETWORK_PATTERNS = [
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
        for package in PACKAGES:
            if not package: continue
            safe_name = package.replace("/", "__")
            print(f"[+] Querying pip index for {package}...")
            res = subprocess.run(["python3", "-m", "pip", "index", "versions", package], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"pypi-{safe_name}-versions.txt").write_text(res.stdout)
            subprocess.run(["python3", "-m", "pip", "download", "--no-deps", package, "-d", str(registry_dir)], capture_output=True)

print(f"[+] Wrote scope artifacts under {OUT}")
