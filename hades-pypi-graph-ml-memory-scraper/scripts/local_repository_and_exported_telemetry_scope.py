#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
OUT = Path(os.environ.get('OUT', 'hp-hades-pypi-graph-ml-memory-scraper-scope'))
OUT.mkdir(parents=True, exist_ok=True)

PACKAGES = ["bramin", "cmd2func", "coolbox", "dynamo-release", "embiggen", "ensmallen", "executor-engine", "executor-http", "funcdesc", "gpsea", "magique", "magique-ai", "mflux-streamlit", "mrbios", "napari-ufish", "nhmpy", "nucbox", "okite", "pantheon-agents", "pantheon-toolsets", "ppkt2synergy", "pyphetools", "rlask", "rsquests", "spateo-release", "synago", "tlask", "ufish", "uprobe"]
PACKAGE_VERSIONS = ["bramin@0.0.2", "bramin@0.0.3", "bramin@0.0.4", "cmd2func@0.2.2", "cmd2func@0.2.3", "coolbox@0.4.1", "coolbox@0.4.2", "dynamo-release@1.5.4", "embiggen@0.11.97", "ensmallen@0.8.101", "executor-engine@0.3.4", "executor-engine@0.3.5", "executor-http@0.1.3", "executor-http@0.1.4", "funcdesc@0.2.2", "funcdesc@0.2.3", "gpsea@0.9.14", "magique@0.6.8", "magique@0.6.9", "magique-ai@0.4.4", "magique-ai@0.4.5", "mflux-streamlit@0.0.3", "mflux-streamlit@0.0.4", "mrbios@0.1.1", "mrbios@0.1.2", "napari-ufish@0.0.2", "napari-ufish@0.0.3", "nhmpy@2.4.7", "nucbox@0.1.2", "nucbox@0.1.3", "okite@0.0.7", "okite@0.0.8", "pantheon-agents@0.6.1", "pantheon-agents@0.6.2", "pantheon-toolsets@0.5.5", "pantheon-toolsets@0.5.6", "ppkt2synergy@0.1.1", "pyphetools@0.9.120", "rlask@3.1.4", "rlask@3.1.5", "rlask@3.1.6", "rlask@3.1.7", "rsquests@2.34.3", "spateo-release@1.1.2", "synago@0.1.1", "synago@0.1.2", "tlask@3.1.4", "ufish@0.1.2", "ufish@0.1.3", "uprobe@0.1.3", "uprobe@0.1.4"]
FILES = ["__init__.py", "_index.js", "/tmp/.bun_ran", "/tmp/tmp.0144018410.lock", "/var/tmp/.gh_update_state", "~/.local/share/updater/update.py", "~/.config/systemd/user/update-monitor.service", "~/.config/systemd/user/gh-token-monitor.service", "~/Library/LaunchAgents/com.user.update-monitor.plist", "~/.local/bin/gh-token-monitor.sh", ".claude/settings.json", ".vscode/tasks.json", "Run Copilot"]
HASHES = []
DOMAINS = ["api.github.com", "github.com"]
URLS = ["https://github.com/oven-sh/bun/releases/download/bun-v1.3.14/", "https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages"]
IPS = []
PROCESS_PATTERNS = ["Runner.Worker", "/proc/{pid}/mem", "task_for_pid", "ReadProcessMemory", "bun run _index.js", "firedalazer"]
NETWORK_PATTERNS = ["Hades - The End for the Damned", "DontRevokeOrItGoesBoom", "TheBeautifulSnadsOfTime", "stygian-cerberus-", "tartarean-charon-"]

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
