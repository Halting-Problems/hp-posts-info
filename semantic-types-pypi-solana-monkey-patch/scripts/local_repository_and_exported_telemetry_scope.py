#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-semantic-types-pypi-solana-monkey-patch-scope"))

VERSIONS = ["0.1.5","0.1.6","semantic-types==0.1.5","semantic-types==0.1.6","solana-keypair","solana-publickey","solana-mev-agent-py","solana-trading-bot","soltrade"]
DOMAINS = ["api.devnet.solana.com","solders.keypair.Keypair"]
URLS = ["https://api.devnet.solana.com"]
HASHES = ["5a4d8480c9d1e82ba102f200258882fb9e694e8fc0343b6982c5540beccdca62"]

# Collect unique indicators
indicators = set()
for group in [VERSIONS, DOMAINS, URLS, HASHES]:
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
            print(f"[+] Querying pip index for {package}...")
            res = subprocess.run(["python3", "-m", "pip", "index", "versions", package], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"pypi-{safe_name}-versions.txt").write_text(res.stdout)
            subprocess.run(["python3", "-m", "pip", "download", "--no-deps", package, "-d", str(registry_dir)], capture_output=True)

print(f"[+] Wrote scope artifacts under {OUT}")
