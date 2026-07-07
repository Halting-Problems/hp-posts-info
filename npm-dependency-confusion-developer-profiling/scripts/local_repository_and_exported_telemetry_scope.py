#!/usr/bin/env python3
"""Generic IOC scope scanner for npm-dependency-confusion-developer-profiling.

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

OUT = Path(os.environ.get("OUT", "hp-npm-dependency-confusion-developer-profiling-ioc-scope"))
CONTENT_INDICATORS = [
  "@capibar.chat/ui-kit@0.0.1-security",
  "@ce-rwb/ce-tools-editor-admin@0.0.1-security",
  "@ce-rwb/ce-tools-editor-core@0.0.1-security",
  "@ce-rwb/ce-tools-editor-render@0.0.1-security",
  "@cloudplatform-single-spa/logaas@0.0.1-security",
  "@data-science/llm@0.0.1-security",
  "@payments-widget/payments-widget-sdk@0.0.1-security",
  "@sber-ecom-core/sberpay-widget@0.0.1-security",
  "@t-in-one/add_app_middleware_token@0.0.1-security",
  "@t-in-one/add_application@0.0.1-security",
  "@t-in-one/add_application_service_token@0.0.1-security",
  "@t-in-one/add_application_tid@0.0.1-security",
  "@t-in-one/application_id_storage_key_token@0.0.1-security",
  "@t-in-one/form_product_token@0.0.1-security",
  "@t-in-one/get_application_hid@0.0.1-security",
  "@t-in-one/only_difference_payload@0.0.1-security",
  "@t-in-one/prefill_bundle_data_token@0.0.1-security",
  "@t-in-one/prefill_credit_data_token@0.0.1-security",
  "@travel-autotests/npm-proto@0.0.1-security",
  "@wb-track/shared-front@0.0.1-security",
  "@wordpress/interactivity@0.0.1-security",
  "@wordpress/interactivity-js-modulepreload@0.0.1-security",
  "oob.moika.tech",
  "https://oob.moika.tech/payload",
  "https://github.cloudplatform-single-spa.io/platform/svp-baas.git",
  "https://docs.cloudplatform-single-spa.io/platform/svp-baas",
  "https://jira.cloudplatform-single-spa.io/projects/PLATFORM",
  "postinstall",
  "npm lifecycle hook",
  "dependency confusion",
  "developer environment fingerprinting",
  "credential reconnaissance",
  "developer context",
  "environment variables",
  "hostname",
  "RECON_ONLY",
  "POST /payload to oob.moika.tech with X-Secret",
  "npm registry metadata lookups for the affected scopes",
  "@capibar.chat/ui-kit",
  "0.0.1-security",
  "@ce-rwb/ce-tools-editor-admin",
  "@ce-rwb/ce-tools-editor-core",
  "@ce-rwb/ce-tools-editor-render",
  "@cloudplatform-single-spa/logaas",
  "@data-science/llm",
  "@payments-widget/payments-widget-sdk",
  "@sber-ecom-core/sberpay-widget",
  "@t-in-one/add_app_middleware_token",
  "@t-in-one/add_application",
  "@t-in-one/add_application_service_token",
  "@t-in-one/add_application_tid",
  "@t-in-one/application_id_storage_key_token",
  "@t-in-one/form_product_token",
  "@t-in-one/get_application_hid",
  "@t-in-one/only_difference_payload",
  "@t-in-one/prefill_bundle_data_token",
  "@t-in-one/prefill_credit_data_token",
  "@travel-autotests/npm-proto",
  "@wb-track/shared-front",
  "@wordpress/interactivity",
  "@wordpress/interactivity-js-modulepreload"
]
PATH_INDICATORS = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "scripts/postinstall.js",
  ".npmrc",
  ".github/workflows/*.yml"
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
