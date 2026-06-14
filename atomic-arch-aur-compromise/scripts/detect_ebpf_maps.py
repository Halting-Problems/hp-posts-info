#!/usr/bin/env python3
"""Detect Atomic Arch pinned eBPF maps.
Exit codes:
  0: Clean (no maps found)
  1: Compromise (at least one map found)
  2: Execution error
"""
import os
import sys
import argparse

MAP_NAMES = ["hidden_pids", "hidden_names", "hidden_inodes"]

def main():
    parser = argparse.ArgumentParser(description="Scan for pinned eBPF maps")
    parser.add_argument("--bpf-dir", default="/sys/fs/bpf", help="BPF directory path")
    args = parser.parse_args()

    bpf_dir = args.bpf_dir
    if not os.path.exists(bpf_dir):
        print(f"[-] BPF directory '{bpf_dir}' does not exist.")
        return 0

    found = []
    for name in MAP_NAMES:
        target = os.path.join(bpf_dir, name)
        if os.path.exists(target):
            print(f"[!] MALICIOUS: Pinned eBPF map '{name}' found at '{target}'")
            found.append(target)

    if found:
        return 1
    
    print("[+] No malicious pinned eBPF maps found.")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[-] Execution failure: {e}", file=sys.stderr)
        sys.exit(2)
