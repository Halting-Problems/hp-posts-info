#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-trapdoor-cross-ecosystem-crypto-stealer-scope"))
SINCE = "2026-05-22T20:20:18Z"
UNTIL = "2026-05-24T23:59:59Z"

PACKAGES = [
  "async-pipeline-builder",
  "build-scripts-utils",
  "chain-key-validator",
  "crypto-credential-scanner",
  "defi-env-auditor",
  "defi-threat-scanner",
  "deployment-key-auditor",
  "dev-env-bootstrapper",
  "eth-wallet-sentinel",
  "llm-context-compressor",
  "mnemonic-safety-check",
  "model-switch-router",
  "node-setup-helpers",
  "project-init-tools",
  "prompt-engineering-toolkit",
  "solidity-deploy-guard",
  "token-usage-tracker",
  "wallet-backup-verifier",
  "wallet-security-checker",
  "web3-secrets-detector",
  "workspace-config-loader",
  "cryptowallet-safety",
  "data-pipeline-check",
  "defi-risk-scanner",
  "env-loader-cli",
  "eth-security-auditor",
  "git-config-sync",
  "solidity-build-guard",
  "move-analyzer-build",
  "move-compiler-tools",
  "move-project-builder",
  "sui-framework-helpers",
  "sui-move-build-helper",
  "sui-sdk-build-utils",
]
VERSIONS = [
  "env-loader-cli@0.1.0",
  "env-loader-cli@0.1.1",
  "eth-security-auditor@0.1.0",
  "sui-framework-helpers@0.1.0",
  "PyPI/env-loader-cli 0.1.0",
  "PyPI/env-loader-cli 0.1.1",
  "PyPI/eth-security-auditor 0.1.0",
  "Crates.io/sui-framework-helpers 0.1.0",
]
FILES = [
  "trap-core.js",
  ".cursorrules",
  "CLAUDE.md",
  "build.rs",
]
DOMAINS = [
  "ddjidd564.github.io",
]
URLS = [
  "https://ddjidd564.github.io/defi-security-best-practices/",
  "https://ddjidd564.github.io/defi-security-best-practices/config.json",
  "https://ddjidd564.github.io/defi-security-best-practices/payloads/compliance-scanner-light.js",
  "https://ddjidd564.github.io/defi-security-best-practices/payloads/risk-profiler.js",
]
IPS = [
]
HASHES = [
]
PROCESS_PATTERNS = [
  "npm -> node trap-core.js",
  "python -> node -e",
  "cargo -> build.rs",
]
NETWORK_PATTERNS = [
  "developer or CI host egress to ddjidd564.github.io",
  "post-install GitHub or AWS credential validation",
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
