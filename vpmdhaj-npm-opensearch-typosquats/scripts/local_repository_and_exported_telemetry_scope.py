#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "@vpmdhaj/devops-tools",
    "@vpmdhaj/elastic-helper",
    "@vpmdhaj/opensearch-setup",
    "@vpmdhaj/search-setup",
    "app-config-utility",
    "elastic-opensearch-helper",
    "env-config-manager",
    "opensearch-config-utility",
    "opensearch-security-scanner",
    "opensearch-setup",
    "opensearch-setup-tool",
    "search-cluster-setup",
    "search-engine-setup",
    "vpmdhaj-opensearch-setup",
    "@vpmdhaj/aws-compat",
    "@vpmdhaj/aws-credential-provider-env",
    "@vpmdhaj/aws-credential-provider-http",
    "@vpmdhaj/aws-sdk-client-opensearch",
    "@vpmdhaj/aws-sdk-client-sts",
    "@vpmdhaj/aws-sdk-credential-provider-node",
    "@vpmdhaj/aws-sdk-types",
    "@vpmdhaj/bun",
    "@vpmdhaj/opensearch",
    "@vpmdhaj/opensearch-project",
    "@vpmdhaj/opensearch-js",
    "@vpmdhaj/sts-client"
]
PACKAGE_VERSIONS = [
    "@vpmdhaj/opensearch-setup@1.0.9102",
    "@vpmdhaj/opensearch-setup@1.0.9103",
    "@vpmdhaj/elastic-helper@1.0.7267",
    "@vpmdhaj/elastic-helper@1.0.7268",
    "@vpmdhaj/elastic-helper@1.0.7269",
    "@vpmdhaj/elastic-helper@1.0.7270",
    "@vpmdhaj/devops-tools@1.0.0",
    "@vpmdhaj/search-setup@1.0.0",
    "app-config-utility@1.0.0",
    "elastic-opensearch-helper@1.0.0",
    "env-config-manager@1.0.0",
    "opensearch-config-utility@1.0.0",
    "opensearch-security-scanner@1.0.0",
    "opensearch-setup@1.0.0",
    "opensearch-setup-tool@1.0.0",
    "search-cluster-setup@1.0.0",
    "search-engine-setup@1.0.0",
    "vpmdhaj-opensearch-setup@1.0.0",
    "@vpmdhaj/aws-compat@1.0.0",
    "@vpmdhaj/aws-credential-provider-env@1.0.0",
    "@vpmdhaj/aws-credential-provider-http@1.0.0",
    "@vpmdhaj/aws-sdk-client-opensearch@1.0.0",
    "@vpmdhaj/aws-sdk-client-sts@1.0.0",
    "@vpmdhaj/aws-sdk-credential-provider-node@1.0.0",
    "@vpmdhaj/aws-sdk-types@1.0.0",
    "@vpmdhaj/bun@1.0.0",
    "@vpmdhaj/opensearch@1.0.0",
    "@vpmdhaj/opensearch-project@1.0.0",
    "@vpmdhaj/opensearch-js@1.0.0",
    "@vpmdhaj/sts-client@1.0.0"
]
HASHES = [
    "a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145"
]
DOMAINS = [
    "aab.sportsontheweb.net",
    "www.sportsontheweb.net"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'hashes': HASHES,
    'domains': DOMAINS
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
