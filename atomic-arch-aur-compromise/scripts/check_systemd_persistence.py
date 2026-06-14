#!/usr/bin/env python3
"""Check systemd unit directories for suspicious persistent services.
Exit codes:
  0: Clean (no indicators found)
  1: Compromise (indicators found)
  2: Execution error
"""
import os
import sys
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Scan systemd services for persistence hooks")
    parser.add_argument("--systemd-dirs", nargs="+", default=[
        "/etc/systemd/system",
        os.path.expanduser("~/.config/systemd/user")
    ], help="Systemd directories to scan")
    args = parser.parse_args()

    found = False
    for directory in args.systemd_dirs:
        dir_path = Path(directory)
        if not dir_path.exists() or not dir_path.is_dir():
            continue

        print(f"[+] Scanning systemd directory: {dir_path}")
        for file in dir_path.glob("*.service"):
            if file.is_file() and os.access(file, os.R_OK):
                content = file.read_text(errors="ignore")
                if "Restart=always" in content and "RestartSec=30" in content:
                    if any(x in content for x in ["deps", "monero", "temp.sh", "onion"]):
                        print(f"[!] MALICIOUS: Suspicious systemd persistence hook found at '{file}'")
                        found = True

    if found:
        return 1
    
    print("[+] No suspicious systemd units found.")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[-] Execution failure: {e}", file=sys.stderr)
        sys.exit(2)
