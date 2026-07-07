#!/usr/bin/env python3
"""Generic IOC scope scanner for trapdoor-cross-ecosystem-crypto-stealer.

Searches repository trees and exported logs for literal IOC values from iocs.json.
Exit codes:
  0: no matches
  1: one or more indicators matched
  2: execution error
"""
import argparse
import fnmatch
import os
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT", "hp-trapdoor-cross-ecosystem-crypto-stealer-ioc-scope"))
CONTENT_INDICATORS = [
  "env-loader-cli@0.1.0",
  "env-loader-cli@0.1.1",
  "eth-security-auditor@0.1.0",
  "sui-framework-helpers@0.1.0",
  "PyPI/env-loader-cli 0.1.0",
  "PyPI/env-loader-cli 0.1.1",
  "PyPI/eth-security-auditor 0.1.0",
  "Crates.io/sui-framework-helpers 0.1.0",
  "async-pipeline-builder@1.0.0",
  "build-scripts-utils@1.0.0",
  "chain-key-validator@1.0.0",
  "crypto-credential-scanner@1.0.0",
  "defi-env-auditor@1.0.0",
  "defi-threat-scanner@1.0.0",
  "deployment-key-auditor@1.0.0",
  "dev-env-bootstrapper@1.0.0",
  "eth-wallet-sentinel@1.0.0",
  "llm-context-compressor@1.0.0",
  "mnemonic-safety-check@1.0.0",
  "model-switch-router@1.0.0",
  "node-setup-helpers@1.0.0",
  "project-init-tools@1.0.0",
  "prompt-engineering-toolkit@1.0.0",
  "solidity-deploy-guard@1.0.0",
  "token-usage-tracker@1.0.0",
  "wallet-backup-verifier@1.0.0",
  "wallet-security-checker@1.0.0",
  "web3-secrets-detector@1.0.0",
  "workspace-config-loader@1.0.0",
  "cryptowallet-safety@1.0.0",
  "data-pipeline-check@1.0.0",
  "defi-risk-scanner@1.0.0",
  "git-config-sync@1.0.0",
  "solidity-build-guard@1.0.0",
  "move-analyzer-build@1.0.0",
  "move-compiler-tools@1.0.0",
  "move-project-builder@1.0.0",
  "sui-move-build-helper@1.0.0",
  "sui-sdk-build-utils@1.0.0",
  "ddjidd564.github.io",
  "https://ddjidd564.github.io/defi-security-best-practices/",
  "https://ddjidd564.github.io/defi-security-best-practices/config.json",
  "https://ddjidd564.github.io/defi-security-best-practices/payloads/compliance-scanner-light.js",
  "https://ddjidd564.github.io/defi-security-best-practices/payloads/risk-profiler.js",
  "npm -> node trap-core.js",
  "python -> node -e",
  "cargo -> build.rs",
  "developer or CI host egress to ddjidd564.github.io",
  "post-install GitHub or AWS credential validation",
  "env-loader-cli",
  "0.1.0",
  "0.1.1",
  "eth-security-auditor",
  "sui-framework-helpers",
  "PyPI/env-loader-cli",
  "PyPI/eth-security-auditor",
  "Crates.io/sui-framework-helpers",
  "async-pipeline-builder",
  "1.0.0",
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
  "git-config-sync",
  "solidity-build-guard",
  "move-analyzer-build",
  "move-compiler-tools",
  "move-project-builder",
  "sui-move-build-helper",
  "sui-sdk-build-utils"
]
PATH_INDICATORS = [
  "trap-core.js",
  ".cursorrules",
  "CLAUDE.md",
  "build.rs"
]
EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}

def _iter_files(root):
    root = Path(root)
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            yield Path(current) / name

def _path_matches(path):
    text = str(path)
    matches = []
    for indicator in PATH_INDICATORS:
        if not indicator:
            continue
        if indicator.startswith(("/", "~")):
            candidate = Path(os.path.expanduser(indicator))
            if candidate.exists() and path == candidate:
                matches.append(indicator)
        if indicator in text or fnmatch.fnmatch(text, indicator) or fnmatch.fnmatch(path.name, indicator):
            matches.append(indicator)
    return matches

def _content_matches(path):
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []
    return [indicator for indicator in CONTENT_INDICATORS if indicator and indicator in content]

def _scan_roots(roots):
    matches = []
    for root in roots:
        if not root:
            continue
        for path in _iter_files(root):
            for indicator in _path_matches(path):
                matches.append(f"{path}: path matched {indicator!r}")
            for indicator in _content_matches(path):
                matches.append(f"{path}: content matched {indicator!r}")
    return matches

def main():
    parser = argparse.ArgumentParser(description="Scan files and logs for Halting Problems IOC values")
    parser.add_argument("roots", nargs="*", default=["."], help="File or directory roots to scan")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log directory")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    indicator_lines = sorted(set(CONTENT_INDICATORS + PATH_INDICATORS))
    (OUT / "ioc-indicators.txt").write_text("\n".join(indicator_lines) + "\n")

    roots = list(args.roots)
    if args.log_root:
        roots.append(args.log_root)
    matches = _scan_roots(roots)
    if matches:
        (OUT / "ioc-scope-matches.txt").write_text("\n".join(matches) + "\n")
        print(f"[!] Found {len(matches)} IOC matches; details written under {OUT}")
        return 1
    print(f"[+] No IOC matches found; indicator inventory written under {OUT}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[-] Execution failure: {exc}", file=sys.stderr)
        sys.exit(2)
