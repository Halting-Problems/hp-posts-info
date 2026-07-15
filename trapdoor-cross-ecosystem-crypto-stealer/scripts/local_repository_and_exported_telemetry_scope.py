#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

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
    "sui-sdk-build-utils"
]
PACKAGE_VERSIONS = [
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
    "sui-sdk-build-utils@1.0.0"
]
FILES = [
    "trap-core.js",
    ".cursorrules",
    "CLAUDE.md",
    "build.rs"
]
DOMAINS = [
    "ddjidd564.github.io"
]
PROCESS_PATTERNS = [
    "npm -> node trap-core.js",
    "python -> node -e",
    "cargo -> build.rs"
]
NETWORK_PATTERNS = [
    "developer or CI host egress to ddjidd564.github.io",
    "post-install GitHub or AWS credential validation"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'domains': DOMAINS,
    'process_patterns': PROCESS_PATTERNS,
    'network_patterns': NETWORK_PATTERNS
}

def main() -> int:
    try:
        runtime_path = Path(__file__).resolve().parents[2] / "scanner_runtime.py"
        spec = importlib.util.spec_from_file_location("hp_scanner_runtime", runtime_path)
        if spec is None or spec.loader is None:
            print(f"scanner runtime not found: {runtime_path}", file=sys.stderr)
            return 2
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        args = list(sys.argv[1:])
        if os.environ.get("LOG_ROOT") and "--log-root" not in args:
            args.extend(["--log-root", os.environ["LOG_ROOT"]])
        if os.environ.get("OUT") and "--out" not in args:
            args.extend(["--out", os.environ["OUT"]])
        return runtime.main(args, PROFILE) if args else 2
    except Exception as exc:
        print(f"scanner execution error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
