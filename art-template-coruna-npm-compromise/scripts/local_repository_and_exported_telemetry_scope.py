#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-art-template-coruna-npm-compromise-scope"))
SINCE = "2026-05-24T00:00:00Z"
UNTIL = "2026-05-24T23:59:59Z"

PACKAGES = [
]
VERSIONS = [
  "art-template 4.13.3",
  "art-template 4.13.5",
  "art-template 4.13.6",
]
FILES = [
  "lib/template-web.js",
  "49554fde7424c31c.js",
]
DOMAINS = [
  "git.youzzjizz.com",
  "v3.jiathis.com",
  "utaq.cfww.shop",
  "cfww.shop",
  "l1ewsu3yjkqeroy.xyz",
  "hm.baidu.com",
]
URLS = [
  "https://git.youzzjizz.com/git.js",
  "https://v3.jiathis.com/code/jia.js?uid=artemplate",
  "https://v3.jiathis.com/code/art.js",
  "https://utaq.cfww.shop/gooll/49554fde7424c31c.js",
  "https://l1ewsu3yjkqeroy.xyz/api/ip-sync/sync",
]
IPS = [
]
HASHES = [
  "f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c (SHA-256, 49554fde7424c31c.js)",
  "8064d4e0322f069b3dba13e7957ff0ca7dab7984 (SHA-1, 49554fde7424c31c.js)",
  "6e79ae622b7ef30f31fdbcc2dc65339e (MD5, 49554fde7424c31c.js)",
  "f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c",
  "8064d4e0322f069b3dba13e7957ff0ca7dab7984",
  "6e79ae622b7ef30f31fdbcc2dc65339e",
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

print(f"[+] Wrote scope artifacts under {OUT}")
