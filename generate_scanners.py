#!/usr/bin/env python3
"""Regenerate generic post scanners from local IOC profiles.

The protected scanner package is intentionally excluded from discovery.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parent
PROTECTED = "shai-hulululud-ai-scanner-disruption-package"
GENERIC = "local_repository_and_exported_telemetry_scope"
NOISY_DOMAINS = {"github.com", "api.github.com", "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "rubygems.org"}


def profile_for(folder: Path) -> dict[str, list[str]]:
    data = json.loads((folder / "iocs.json").read_text(encoding="utf-8"))
    assets = data.get("affected_assets", {})
    iocs = data.get("iocs", {})
    package_versions = list(iocs.get("package_versions", []))
    if not package_versions:
        package_versions = [str(v).replace(" v", "@", 1) for v in assets.get("versions", []) if " v" in str(v)]
    return {
        "packages": [str(v) for v in assets.get("packages", []) if v],
        "package_versions": [str(v) for v in package_versions if v],
        "files": [str(v) for v in iocs.get("files", []) if v],
        "hashes": [str(v) for v in iocs.get("hashes", []) if len(str(v)) in {32, 40, 64, 96, 128} and all(c in "0123456789abcdefABCDEF" for c in str(v))],
        # URLs are references, not default detector selectors.
        "domains": [str(v) for v in iocs.get("domains", []) if str(v).lower() not in NOISY_DOMAINS],
        "urls": [],
        "ips": [str(v) for v in iocs.get("ips", []) if v],
        "process_patterns": [str(v) for v in iocs.get("process_patterns", []) if v],
        "network_patterns": [str(v) for v in iocs.get("network_patterns", []) if v],
    }


def render(profile: dict[str, list[str]]) -> str:
    active = {key: value for key, value in profile.items() if value}
    constants = "\n".join(f"{key.upper()} = {json.dumps(value, indent=4)}" for key, value in active.items())
    profile_expr = "{\n" + ",\n".join(f"    {key!r}: {key.upper()}" for key in active) + "\n}"
    return f'''#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

{constants}
PROFILE = {profile_expr}

def main() -> int:
    try:
        runtime_path = Path(__file__).resolve().parents[2] / "scanner_runtime.py"
        spec = importlib.util.spec_from_file_location("hp_scanner_runtime", runtime_path)
        if spec is None or spec.loader is None:
            print(f"scanner runtime not found: {{runtime_path}}", file=sys.stderr)
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
        print(f"scanner execution error: {{exc}}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
'''


def main() -> int:
    count = 0
    for folder in sorted(ROOT.iterdir()):
        if not folder.is_dir() or folder.name == PROTECTED or folder.name.startswith("."):
            continue
        scripts = folder / "scripts"
        targets = sorted(scripts.glob("local_repository_and_exported_telemetry_scope*.py"))
        for target in targets:
            source = target.read_text(encoding="utf-8", errors="ignore")
            # All files using the legacy local-repository name are generated
            # wrappers. Dedicated product-specific filenames are left intact.
            scripts.mkdir(exist_ok=True)
            profile = profile_for(folder)
            target.write_text(render(profile), encoding="utf-8")
            count += 1
    print(f"regenerated {count} generic scanners")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
