#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGE_VERSIONS = [
    "agenda-sample-yard 0.1.1",
    "bot9evil 0.1.0",
    "fetchrootx2 0.0.1",
    "soufetchabc 0.0.3",
    "lambeth71b 0.0.1"
]
FILES = [
    "payload.rb",
    "script.rb",
    "evil.rb",
    "yardload.rb",
    "yard_plugin.rb",
    "exploit.rb",
    "extconf.rb",
    "fetcher.rb",
    "/tmp/gemhome/.gem/credentials",
    "/tmp/rubydocran_*",
    "lib/result.txt",
    "x.gemspec"
]
HASHES = [
    "239440c830e17530dda0a8a06ed2708860998750a1e3ed2239e919465dc59420",
    "c2d6bcacc88177e0f2c8c262726f86f37e671b1692c8bc135bac4b610ddcf31a",
    "34212b88108cab6ded037257d6fbc79a61b4c2ea8ecddc6c513b5aad1f308638",
    "2e4e099275efb8f886824a8eccdc595e624cd08ebb1772bd427710e08ff3ab24",
    "94d6c0b589704c8cc75e19f7250d6bfda473266dd7dd7e23fd14bd1bb972a717"
]
DOMAINS = [
    "moderngov.lambeth.gov.uk",
    "democracy.wandsworth.gov.uk",
    "moderngov.southwark.gov.uk"
]
PROCESS_PATTERNS = [
    "ruby writing /tmp/gemhome/.gem/credentials",
    "ruby running gem build",
    "ruby running gem push",
    "ruby Net::HTTP::Post to RubyGems"
]
NETWORK_PATTERNS = [
    "POST hxxps://rubygems.org/api/v1/gems",
    "GET ModernGov mgCalendarMonthView.aspx with User-Agent Mozilla/5.0"
]
PROFILE = {
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
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
