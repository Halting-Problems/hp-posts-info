#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
OUT = Path(os.environ.get('OUT', 'hp-miasma-npm-phantom-gyp-worm-scope'))
OUT.mkdir(parents=True, exist_ok=True)

PACKAGES = ["@evolvconsulting/evolv-coder-lite", "@jagreehal/workflow", "@vapi-ai/server-sdk", "ai-sdk-ollama", "autotel", "autotel-adapters", "autotel-audit", "autotel-aws", "autotel-backends", "autotel-cli", "autotel-cloudflare", "autotel-devtools", "autotel-drizzle", "autotel-edge", "autotel-eventcatalog", "autotel-hono", "autotel-mcp", "awaitly", "awaitly-analyze", "awaitly-libsql"]
PACKAGE_VERSIONS = ["@vapi-ai/server-sdk@0.11.1", "@vapi-ai/server-sdk@0.11.2", "@vapi-ai/server-sdk@1.2.1", "@vapi-ai/server-sdk@1.2.2", "ai-sdk-ollama@0.13.1", "ai-sdk-ollama@1.1.1", "ai-sdk-ollama@2.2.1", "ai-sdk-ollama@3.8.5", "@evolvconsulting/evolv-coder-lite@1.2.0", "@jagreehal/workflow@1.16.1"]
FILES = ["binding.gyp", "index.js", "stub.c"]
HASHES = ["288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a", "ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90", "5926b86b642e00672252953eb30d8f75cfb7797fe3118bd6fa2cfbee92905d61", "ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108", "da39146ef451d1b174a24d00b1e2a45cd38d54e849737f8f35333dcb22175707"]
DOMAINS = ["api.github.com", "github.com"]
URLS = ["https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/"]
IPS = []
PROCESS_PATTERNS = ["node-gyp rebuild", "node index.js", "Runner.Worker", "/proc/{pid}/mem", "gh auth token", "sudo python3"]
NETWORK_PATTERNS = ["thebeautifulmarchoftime", "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner", "Miasma - The Spreading Blight"]

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return f"__READ_ERROR__:{path}:{exc}"

def scan_tree(base: Path, indicators: set[str]) -> list[str]:
    matches = []
    skip = {".git", "node_modules", "vendor", "dist", ".venv", "__pycache__"}
    for current_root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            path = Path(current_root) / name
            text = read_text(path)
            for indicator in indicators:
                if indicator and indicator in text:
                    matches.append(f"{path}: found {indicator!r}")
    return matches

indicators = set()
for group in [PACKAGES, PACKAGE_VERSIONS, FILES, HASHES, DOMAINS, URLS, IPS, PROCESS_PATTERNS, NETWORK_PATTERNS]:
    indicators.update(group)

(OUT / "indicators.txt").write_text("\n".join(sorted(indicators)) + "\n", encoding="utf-8")
matches = scan_tree(ROOT, indicators)
(OUT / "matches.txt").write_text("\n".join(matches) + ("\n" if matches else ""), encoding="utf-8")
print(f"[+] wrote {len(indicators)} selectors and {len(matches)} matches under {OUT}")
