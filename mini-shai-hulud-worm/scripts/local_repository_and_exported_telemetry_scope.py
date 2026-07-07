#!/usr/bin/env python3
"""Generic IOC scope scanner for mini-shai-hulud-worm.

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

OUT = Path(os.environ.get("OUT", "hp-mini-shai-hulud-worm-ioc-scope"))
CONTENT_INDICATORS = [
  "@tanstack/react-router@1.169.5",
  "@tanstack/react-router@1.169.8",
  "@tanstack/vue-router@1.169.5",
  "@tanstack/vue-router@1.169.8",
  "@tanstack/solid-router@1.169.5",
  "@tanstack/solid-router@1.169.8",
  "@tanstack/react-start@1.167.68",
  "@tanstack/react-start@1.167.71",
  "@antv/g2@4.2.8",
  "@antv/g6@4.8.24",
  "nx-console@18.95.0",
  "@tanstack/router-core@1.169.5",
  "@antv/x6@2.2.0",
  "@antv/l7@2.19.0",
  "@antv/s2@1.30.0",
  "@antv/f2@4.1.0",
  "echarts-for-react@3.0.0",
  "timeago.js@4.0.2",
  "size-sensor@1.0.1",
  "canvas-nest.js@2.0.4",
  "@sap/cds@7.9.2",
  "@sap/cds-dk@7.9.2",
  "opensearch-py@2.5.0",
  "lite-llm@1.34.0",
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
  "filev2.getsession.org",
  "api.masscan.cloud",
  "git-tanstack.com",
  "t.m-kosche.com",
  "www.endorlabs.com",
  "www.microsoft.com",
  "www[.]sentinelone[.]com",
  "https://filev2.getsession.org/upload",
  "https://api.masscan.cloud/ping",
  "https://www.endorlabs.com/blog/mini-shai-hulud-npm-worm-hits-sap-developer-packages",
  "https://tanstack.com/blog/postmortem-cve-2026-45321",
  "https://www.microsoft.com/en-us/security/blog/hunting-the-shai-hulud-supply-chain-worm",
  "https://www.sentinelone.com/blog/anatomy-of-cve-2026-45321",
  "@tanstack/react-router",
  "1.169.5",
  "1.169.8",
  "@tanstack/vue-router",
  "@tanstack/solid-router",
  "@tanstack/react-start",
  "1.167.68",
  "1.167.71",
  "@antv/g2",
  "4.2.8",
  "@antv/g6",
  "4.8.24",
  "nx-console",
  "18.95.0",
  "@tanstack/router-core",
  "@antv/x6",
  "2.2.0",
  "@antv/l7",
  "2.19.0",
  "@antv/s2",
  "1.30.0",
  "@antv/f2",
  "4.1.0",
  "echarts-for-react",
  "3.0.0",
  "timeago.js",
  "4.0.2",
  "size-sensor",
  "1.0.1",
  "canvas-nest.js",
  "2.0.4",
  "@sap/cds",
  "7.9.2",
  "@sap/cds-dk",
  "opensearch-py",
  "2.5.0",
  "lite-llm",
  "1.34.0"
]
PATH_INDICATORS = [
  "router_init.js",
  "setup_bun.js",
  "bun_environment.js",
  "transformers.pyz",
  "gh-token-monitor"
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
