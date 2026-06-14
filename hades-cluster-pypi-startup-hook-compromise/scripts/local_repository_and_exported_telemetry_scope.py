#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-hades-cluster-pypi-startup-hook-compromise-scope"))

VERSIONS = ["bramin==0.0.2","bramin==0.0.3","bramin==0.0.4","cmd2func==0.2.2","cmd2func==0.2.3","coolbox==0.4.1","coolbox==0.4.2","dynamo-release==1.5.4","executor-engine==0.3.4","executor-engine==0.3.5","executor-http==0.1.3","executor-http==0.1.4","funcdesc==0.2.2","funcdesc==0.2.3","magique==0.6.8","magique==0.6.9","magique-ai==0.4.4","magique-ai==0.4.5","mrbios==0.1.1","mrbios==0.1.2","napari-ufish==0.0.2","napari-ufish==0.0.3","nucbox==0.1.2","nucbox==0.1.3","okite==0.0.7","okite==0.0.8","pantheon-agents==0.6.1","pantheon-agents==0.6.2","pantheon-toolsets==0.5.5","pantheon-toolsets==0.5.6","spateo-release==1.1.2","synago==0.1.1","synago==0.1.2","ufish==0.1.2","ufish==0.1.3","uprobe==0.1.3","uprobe==0.1.4","dreamgen==1.8.1","embiggen==0.11.97","ensmallen==0.8.101","gpsea==0.9.14","instructor-mcp==1.15.2","instructor-mcp==1.15.3","langchain-core-mcp==1.4.2","langchain-core-mcp==1.4.3","mem8==6.0.1","mflux-streamlit==0.0.3","mflux-streamlit==0.0.4","openai-mcp==2.41.1","openai-mcp==2.41.2","orchestr8-platform==3.3.2","phenopacket-store-toolkit==0.1.7","ppkt2synergy==0.1.1","pyphetools==0.9.120","ray-mcp-server==0.2.1","rlask==3.1.7","rsquests==2.34.3","tiktoken-mcp==0.13.1","tiktoken-mcp==0.13.2","tlask==3.1.4"]
FILES = ["*-setup.pth","langchain_core-setup.pth","_index.js","ensmallen_haswell.abi3.so","ensmallen_core2.abi3.so"]
HASHES = ["dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","6d332f814f15f19758d65026bbfd0a8c49671b319ec77b8fa1b27fc48afff7d9","6506d31707a39949f89534bf9705bcf889f1ecae3dbc6f4ff88d67a8be3d01b2"]
PROCESS_PATTERNS = ["Python startup loads a *-setup.pth hook","Bun executes _index.js from a Python environment"]

# Collect unique indicators
indicators = set()
for group in [VERSIONS, FILES, HASHES, PROCESS_PATTERNS]:
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
