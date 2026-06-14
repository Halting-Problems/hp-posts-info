#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-sicoob-sdk-nuget-certificate-exfiltration-scope"))

PACKAGES = ["Sicoob.Sdk","Sicoob.Sdk@2.0.0","Sicoob.Sdk@2.0.1","Sicoob.Sdk@2.0.2","Sicoob.Sdk@2.0.3","Sicoob.Sdk@2.0.4"]
VERSIONS = ["2.0.0","2.0.1","2.0.2","2.0.3","2.0.4"]
FILES = ["lib/net8.0/Sicoob.Sdk.dll"]
DOMAINS = ["o4511335034847232.ingest.de.sentry.io","Sicoob.Sdk.dll"]
URLS = ["https://d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232.ingest.de.sentry.io/4511337546317904"]
HASHES = ["7d2332e76c266509cdec8b552ccc839f50c28e6b01070071257bd3f57d1d9da2","f0dff53969080584560b2971411415bdf9064d5a5a50185c4ae018943e7d5cbe","94eb8da6703dd073184015c9e3cb34e9b6153fc499c9cb1a7db6e4361ec349dd","ac9dc55f13d973e05865e9674c8b8e6744e7fbfca3355199b292f614f13ac7bc","190dbcafa776e8cc221106414b8fbd68252d98438c5e46b8449788fbe70316a4","d565e3f03d0b1a7c8935d7ff94237316"]

# Collect unique indicators
indicators = set()
for group in [PACKAGES, VERSIONS, FILES, DOMAINS, URLS, HASHES]:
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

print(f"[+] Wrote scope artifacts under {OUT}")
