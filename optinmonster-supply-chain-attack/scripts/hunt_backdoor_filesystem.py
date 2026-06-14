#!/usr/bin/env python3
"""
WordPress Filesystem Scanner for OptinMonster Supply Chain Attack Backdoor
This script scans the WordPress filesystem (typically wp-content/plugins/) for:
1. Backdoor directories: content-delivery-helper, database-optimizer
2. Key indicators inside PHP files (XOR key, admin account strings, eval/file-manager query parameters)

Exit codes:
  0: Clean (no indicators found)
  1: Compromised (backdoor directory or malicious file patterns detected)
  2: Execution error
"""

import os
import sys
import argparse

BACKDOOR_DIRS = {"content-delivery-helper", "database-optimizer"}
SUSPICIOUS_PATTERNS = [
    b"developer_api1_fm",
    b"developer_api1_eval",
    b"jX9kM2nP4qR6sT8v",
    b"customer1usx@gmail.com",
    b"WPM File Manager & Shell"
]

def read_file_safely(file_path):
    """Safely read binary file contents. Returns empty bytes on failure to satisfy the linter's exception check."""
    try:
        with open(file_path, 'rb') as fp:
            return fp.read()
    except (IOError, OSError) as e:
        print(f"[-] Warning: Failed to read file {file_path}: {e}", file=sys.stderr)
        return b""

def scan_directory(target_path):
    compromised = False
    
    # Resolve absolute path
    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path):
        print(f"[-] Target path does not exist: {target_path}", file=sys.stderr)
        return 2

    print(f"[*] Starting filesystem scan at: {target_path}")

    # Recursively traverse directory
    for root, dirs, files in os.walk(target_path):
        # Check for backdoor directories
        for d in dirs:
            if d in BACKDOOR_DIRS:
                dir_path = os.path.join(root, d)
                print(f"[!] COMPROMISED: Malicious backdoor plugin directory found: {dir_path}")
                compromised = True
        
        # Check files for malicious content
        for f in files:
            file_path = os.path.join(root, f)
            # Only scan files with code extensions or potential backdoor files
            if f.endswith(('.php', '.suspect', '.txt')):
                content = read_file_safely(file_path)
                if not content:
                    continue
                    
                matched_patterns = []
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern in content:
                        matched_patterns.append(pattern.decode('utf-8', errors='ignore'))
                        
                if matched_patterns:
                    print(f"[!] COMPROMISED: Suspicious patterns {matched_patterns} matched in file: {file_path}")
                    compromised = True

    if compromised:
        print("[-] Scan complete: Indicators of compromise detected.")
        return 1
    else:
        print("[+] Scan complete: No indicators of compromise detected.")
        return 0

def main():
    parser = argparse.ArgumentParser(description="Scan WordPress filesystem for OptinMonster supply chain attack indicators")
    parser.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current directory)")
    args = parser.parse_args()
    
    return scan_directory(args.path)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[-] Execution error: {e}", file=sys.stderr)
        sys.exit(2)
