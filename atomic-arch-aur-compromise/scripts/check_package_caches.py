#!/usr/bin/env python3
"""Check NPM and Bun cache directories for compromised dependency packages.
Exit codes:
  0: Clean (no indicators found)
  1: Compromise (indicators found)
  2: Execution error
"""
import os
import sys
import argparse
from pathlib import Path

TARGETS = ["atomic-lockfile", "js-digest"]

def main():
    parser = argparse.ArgumentParser(description="Scan NPM and Bun cache directories")
    parser.add_argument("--npm-cache", default=os.path.expanduser("~/.npm/_cacache"), help="Path to NPM cache")
    parser.add_argument("--bun-cache", default=os.path.expanduser("~/.bun/install/cache"), help="Path to Bun cache")
    args = parser.parse_args()

    found = False

    # Check NPM cache
    npm_path = Path(args.npm_cache)
    if npm_path.exists() and npm_path.is_dir():
        print(f"[+] Scanning NPM cache at: {npm_path}")
        for root, _, files in os.walk(npm_path):
            for file in files:
                filepath = Path(root) / file
                if filepath.is_file() and os.access(filepath, os.R_OK):
                    content = filepath.read_text(errors="ignore")
                    for target in TARGETS:
                        if target in content:
                            print(f"[!] MALICIOUS: Found NPM cache reference to '{target}' in '{filepath}'")
                            found = True

    # Check Bun cache
    bun_path = Path(args.bun_cache)
    if bun_path.exists() and bun_path.is_dir():
        print(f"[+] Scanning Bun cache at: {bun_path}")
        for root, _, files in os.walk(bun_path):
            for file in files:
                filepath = Path(root) / file
                if filepath.is_file() and os.access(filepath, os.R_OK):
                    content = filepath.read_text(errors="ignore")
                    for target in TARGETS:
                        if target in content:
                            print(f"[!] MALICIOUS: Found Bun cache reference to '{target}' in '{filepath}'")
                            found = True

    if found:
        return 1
    
    print("[+] No indicators found in package caches.")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[-] Execution failure: {e}", file=sys.stderr)
        sys.exit(2)
