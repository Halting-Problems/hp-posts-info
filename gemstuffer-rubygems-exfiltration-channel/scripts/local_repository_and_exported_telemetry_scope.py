#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-gemstuffer-rubygems-exfiltration-channel-scope"))
SINCE = "2026-05-28T00:00:00Z"
UNTIL = "2026-05-28T23:59:59Z"

PACKAGES = [
]
VERSIONS = [
  "agenda-sample-yard 0.1.1",
  "bot9evil 0.1.0",
  "fetchrootx2 0.0.1",
  "soufetchabc 0.0.3",
  "lambeth71b 0.0.1",
]
FILES = [
  "payload.rb",
  "script.rb",
  "evil.rb",
  "yardload.rb",
  "yard_plugin.rb",
  "exploit.rb",
  "extconf.rb",
  "fetcher.rb",
  "/tmp/gemhome/.gem/credentials",
  "/tmp/rubydocran_*",
  "lib/result.txt",
  "x.gemspec",
]
DOMAINS = [
  "rubygems.org",
  "moderngov.lambeth.gov.uk",
  "democracy.wandsworth.gov.uk",
  "moderngov.southwark.gov.uk",
]
URLS = [
  "https://rubygems.org/api/v1/gems",
  "https://moderngov.lambeth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1",
  "https://democracy.wandsworth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1",
  "https://moderngov.southwark.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1",
]
IPS = [
]
HASHES = [
  "239440c830e17530dda0a8a06ed2708860998750a1e3ed2239e919465dc59420",
  "c2d6bcacc88177e0f2c8c262726f86f37e671b1692c8bc135bac4b610ddcf31a",
  "34212b88108cab6ded037257d6fbc79a61b4c2ea8ecddc6c513b5aad1f308638",
  "2e4e099275efb8f886824a8eccdc595e624cd08ebb1772bd427710e08ff3ab24",
  "94d6c0b589704c8cc75e19f7250d6bfda473266dd7dd7e23fd14bd1bb972a717",
]
PROCESS_PATTERNS = [
  "ruby writing /tmp/gemhome/.gem/credentials",
  "ruby running gem build",
  "ruby running gem push",
  "ruby Net::HTTP::Post to RubyGems",
]
NETWORK_PATTERNS = [
  "POST hxxps://rubygems.org/api/v1/gems",
  "GET ModernGov mgCalendarMonthView.aspx with User-Agent Mozilla/5.0",
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
