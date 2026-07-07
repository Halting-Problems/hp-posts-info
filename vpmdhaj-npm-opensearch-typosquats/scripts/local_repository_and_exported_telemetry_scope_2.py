#!/usr/bin/env python3
"""Generic IOC scope scanner for vpmdhaj-npm-opensearch-typosquats.

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

OUT = Path(os.environ.get("OUT", "hp-vpmdhaj-npm-opensearch-typosquats-ioc-scope"))
CONTENT_INDICATORS = [
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
  "@vpmdhaj/sts-client@1.0.0",
  "a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145",
  "9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf",
  "aab[.]sportsontheweb[.]net",
  "www[.]sportsontheweb[.]net",
  "@vpmdhaj/opensearch-setup",
  "1.0.9102",
  "1.0.9103",
  "@vpmdhaj/elastic-helper",
  "1.0.7267",
  "1.0.7268",
  "1.0.7269",
  "1.0.7270",
  "@vpmdhaj/devops-tools",
  "1.0.0",
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
PATH_INDICATORS = []
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
