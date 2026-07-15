#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "bramin",
    "cmd2func",
    "coolbox",
    "dynamo-release",
    "embiggen",
    "ensmallen",
    "executor-engine",
    "executor-http",
    "funcdesc",
    "gpsea",
    "magique",
    "magique-ai",
    "mflux-streamlit",
    "mrbios",
    "napari-ufish",
    "nhmpy",
    "nucbox",
    "okite",
    "pantheon-agents",
    "pantheon-toolsets",
    "ppkt2synergy",
    "pyphetools",
    "rlask",
    "rsquests",
    "spateo-release",
    "synago",
    "tlask",
    "ufish",
    "uprobe"
]
PACKAGE_VERSIONS = [
    "bramin@0.0.2",
    "bramin@0.0.3",
    "bramin@0.0.4",
    "cmd2func@0.2.2",
    "cmd2func@0.2.3",
    "coolbox@0.4.1",
    "coolbox@0.4.2",
    "dynamo-release@1.5.4",
    "embiggen@0.11.97",
    "ensmallen@0.8.101",
    "executor-engine@0.3.4",
    "executor-engine@0.3.5",
    "executor-http@0.1.3",
    "executor-http@0.1.4",
    "funcdesc@0.2.2",
    "funcdesc@0.2.3",
    "gpsea@0.9.14",
    "magique@0.6.8",
    "magique@0.6.9",
    "magique-ai@0.4.4",
    "magique-ai@0.4.5",
    "mflux-streamlit@0.0.3",
    "mflux-streamlit@0.0.4",
    "mrbios@0.1.1",
    "mrbios@0.1.2",
    "napari-ufish@0.0.2",
    "napari-ufish@0.0.3",
    "nhmpy@2.4.7",
    "nucbox@0.1.2",
    "nucbox@0.1.3",
    "okite@0.0.7",
    "okite@0.0.8",
    "pantheon-agents@0.6.1",
    "pantheon-agents@0.6.2",
    "pantheon-toolsets@0.5.5",
    "pantheon-toolsets@0.5.6",
    "ppkt2synergy@0.1.1",
    "pyphetools@0.9.120",
    "rlask@3.1.4",
    "rlask@3.1.5",
    "rlask@3.1.6",
    "rlask@3.1.7",
    "rsquests@2.34.3",
    "spateo-release@1.1.2",
    "synago@0.1.1",
    "synago@0.1.2",
    "tlask@3.1.4",
    "ufish@0.1.2",
    "ufish@0.1.3",
    "uprobe@0.1.3",
    "uprobe@0.1.4"
]
FILES = [
    "__init__.py",
    "_index.js",
    "/tmp/.bun_ran",
    "/tmp/tmp.0144018410.lock",
    "/var/tmp/.gh_update_state",
    "~/.local/share/updater/update.py",
    "~/.config/systemd/user/update-monitor.service",
    "~/.config/systemd/user/gh-token-monitor.service",
    "~/Library/LaunchAgents/com.user.update-monitor.plist",
    "~/.local/bin/gh-token-monitor.sh",
    ".claude/settings.json",
    ".vscode/tasks.json",
    "Run Copilot"
]
PROCESS_PATTERNS = [
    "Runner.Worker",
    "/proc/{pid}/mem",
    "task_for_pid",
    "ReadProcessMemory",
    "bun run _index.js",
    "firedalazer"
]
NETWORK_PATTERNS = [
    "Hades - The End for the Damned",
    "DontRevokeOrItGoesBoom",
    "TheBeautifulSnadsOfTime",
    "stygian-cerberus-",
    "tartarean-charon-"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
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
