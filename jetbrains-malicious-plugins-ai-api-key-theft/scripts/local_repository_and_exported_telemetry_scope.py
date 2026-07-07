#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path
from typing import Iterable

PLUGIN_IDS = [
    "org.sm.yms.toolkit",
    "com.json.simple.kit",
    "org.bug.find.tools",
    "org.translate.ai.simple",
    "com.yy.test.ai.simple",
    "com.dev.ai.toolkit",
    "com.json.view.simple",
    "com.my.git.ai.kit",
    "org.check.ai.ds",
    "com.review.tool.code",
    "org.code.assist.dev.tool",
    "com.coder.ai.dpt",
    "com.my.code.tools",
    "ord.cp.code.ai.kit",
    "com.dp.git.ai.tool",
]

PLUGIN_NAMES = [
    "DeepSeek Junit Test",
    "DeepSeek Git Commit",
    "DeepSeek FindBugs",
    "DeepSeek AI Chat",
    "DeepSeek Dev AI",
    "DeepSeek AI Coding",
    "AI FindBugs",
    "AI Git Commitor",
    "AI Coder Review",
    "DeepSeek Coder AI",
    "AI Coder Assistant",
    "DeepSeek Code Review",
    "CodeGPT AI Assistant",
    "DeepSeek AI Assist",
    "Coding Simple Tool",
]

PUBLISHERS = [
    "mycode",
    "misshewei",
    "keteme",
    "simpledev",
    "skyblue",
    "dialycode",
    "947cb4c8-5db1-4cf0-8182-0aae7c433bb3",
]

REFERENCE_DOMAINS = [
    "stepsecurity.io",
    "blog.jetbrains.com",
    "plugins.jetbrains.com",
]

REFERENCE_URLS = [
    "https://www.stepsecurity.io/blog/jetbrains-malicious-plugins-ai-api-key-theft",
    "https://blog.jetbrains.com/platform/2026/06/marketplace-ecosystem-security-update-malicious-ai-plugins/",
    "https://plugins.jetbrains.com/plugin/org.sm.yms.toolkit",
    "https://plugins.jetbrains.com/plugin/com.json.simple.kit",
    "https://plugins.jetbrains.com/plugin/com.dp.git.ai.tool",
]

NETWORK_IOCS = [
    "39[.]107[.]60[.]51",
    "http://39.107.60.51/api/software/key",
    "http://39.107.60.51/api/software/check",
    "X-Api-Key: F48D2AA7CF341F782C1D",
]

URLS = ["http://39.107.60.51/api/software/key","http://39.107.60.51/api/software/check"]
IPS = ["39.107.60.51"]

# Collect unique indicators
indicators = set()
for group in [URLS, IPS]:
    for val in group:
        if val:
            indicators.add(val)

INDICATORS = sorted({*PLUGIN_IDS, *PLUGIN_NAMES, *PUBLISHERS, *REFERENCE_DOMAINS, *REFERENCE_URLS, *NETWORK_IOCS, *NETWORK_PATTERNS})


def write_indicator_file(out_dir: Path, indicators: Iterable[str]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    indicator_file = out_dir / "ioc-indicators.txt"
    with indicator_file.open("w", encoding="utf-8") as handle:
        for item in sorted(set(indicators)):
            handle.write(item + "\n")
    return indicator_file


def scan_tree(root: Path, indicators: Iterable[str]) -> list[str]:
    matches: list[str] = []
    exclude_dirs = {".git", "node_modules", "dist", "vendor", "__pycache__"}
    indicator_list = list(indicators)

    if not root.exists():
        return matches

    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for filename in filenames:
            path = Path(current_root) / filename
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for indicator in indicator_list:
                if indicator in content:
                    matches.append(f"{path}: found '{indicator}'")
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Scope JetBrains malicious plugin indicators in a local tree or telemetry export.")
    parser.add_argument("root", nargs="?", default=".", help="directory tree to scan")
    parser.add_argument("--telemetry-root", default=os.environ.get("LOG_ROOT", ""), help="optional telemetry/export directory to scan")
    parser.add_argument("--out", default=os.environ.get("OUT", "hp-jetbrains-malicious-plugins-ai-api-key-theft-scope"), help="output directory")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    telemetry_root = Path(args.telemetry_root).resolve() if args.telemetry_root else None
    out_dir = Path(args.out).resolve()

    indicator_file = write_indicator_file(out_dir, INDICATORS)
    repo_matches = scan_tree(root, INDICATORS)
    repo_match_file = out_dir / "repository-indicator-matches.txt"
    if repo_matches:
        repo_match_file.write_text("\n".join(repo_matches) + "\n", encoding="utf-8")

    telemetry_matches: list[str] = []
    if telemetry_root and telemetry_root.exists():
        telemetry_matches = scan_tree(telemetry_root, INDICATORS)
        telemetry_match_file = out_dir / "exported-telemetry-indicator-matches.txt"
        if telemetry_matches:
            telemetry_match_file.write_text("\n".join(telemetry_matches) + "\n", encoding="utf-8")

    summary = {
        "root": str(root),
        "telemetry_root": str(telemetry_root) if telemetry_root else None,
        "out_dir": str(out_dir),
        "indicator_file": str(indicator_file),
        "repository_match_count": len(repo_matches),
        "telemetry_match_count": len(telemetry_matches),
    }
    (out_dir / "scan-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"[+] Wrote indicator file: {indicator_file}")
    print(f"[+] Repository matches: {len(repo_matches)}")
    if telemetry_root and telemetry_root.exists():
        print(f"[+] Telemetry matches: {len(telemetry_matches)}")
    print(f"[+] Summary written to: {out_dir / 'scan-summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
