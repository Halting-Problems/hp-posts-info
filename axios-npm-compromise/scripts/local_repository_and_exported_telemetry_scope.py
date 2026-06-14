#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-axios-npm-compromise-scope"))

PACKAGES = ["axios","plain-crypto-js"]
VERSIONS = ["axios@1.14.1","axios@0.30.4","plain-crypto-js@4.2.1"]
FILES = ["/Library/Caches/com.apple.act.mond","%PROGRAMDATA%\\\\wt.exe","%PROGRAMDATA%\\\\system.bat","/tmp/ld.py"]
DOMAINS = ["sfrclak.com","cloud.google.com","www.elastic.co","com.apple.act.mond"]
URLS = ["http://sfrclak.com:8000/6202033","https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package","https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections","https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all","https://github.com/advisories/GHSA-fw8c-xr5c-95f9"]
IPS = ["142.11.206.73"]
HASHES = ["e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09","92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a","617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101","fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf","6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7","ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c","e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff"]

# Collect unique indicators
indicators = set()
for group in [PACKAGES, VERSIONS, FILES, DOMAINS, URLS, IPS, HASHES]:
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
            pass  # pass # return or raise not needed here

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
                pass  # pass # return or raise not needed here
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
