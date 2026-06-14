#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-ironworm-npm-ebpf-stealer-worm-scope"))

PACKAGES = ["ai3@0.3.5","aonote@0.11.1","arjson@0.1.4","arnext@0.1.5","arnext-arkb@0.0.2","atomic-notes@0.5.3","create-arnext-app@0.0.10","cwao@0.5.6","cwao-tools@0.3.1","cwao-units@0.8.3","fpjson-lang@0.1.7","hbsig@0.3.2","monade@0.0.7","roidjs@0.1.7","test-ajs@0.1.19","test-weavedb-sdk@1.1.1","testnpmnmp@1.0.21","wao@0.41.2","warp-contracts-plugin-deploy-test@3.0.1","wdb-cli@0.1.1","wdb-core@0.1.2","wdb-sdk@0.1.2","weavedb-base@0.45.3","weavedb-client@0.45.3","weavedb-console@0.2.1","weavedb-contracts@0.45.2","weavedb-exm-sdk@0.7.4","weavedb-exm-sdk-web@0.7.4","weavedb-lite@0.1.1","weavedb-node-client@0.45.3","weavedb-offchain@0.45.4","weavedb-sdk-base@0.21.1","weavedb-sdk-node@0.45.3","weavedb-tools@0.45.3","weavedb-warp-contracts-plugin-deploy@1.0.11","zkjson@0.8.5"]
FILES = ["tools/setup"]
HASHES = ["7750bab1a6c48831b5a889e6b799d1684d0a4f2a"]
PROCESS_PATTERNS = ["preinstall hook launching custom Rust binary","unusual loading of eBPF programs"]

# Collect unique indicators
indicators = set()
for group in [PACKAGES, FILES, HASHES, PROCESS_PATTERNS]:
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
