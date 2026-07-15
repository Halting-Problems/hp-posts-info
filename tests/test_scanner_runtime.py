import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from generate_scanners import profile_for


ROOT = Path(__file__).parent.parent
RUNTIME = ROOT / "scanner_runtime.py"
WRAPPER_MARKER = "Generated offline hunt scanner; regenerate with generate_scanners.py."
WRAPPERS = sorted(
    path
    for path in ROOT.glob("*/scripts/local_repository_and_exported_telemetry_scope*.py")
    if WRAPPER_MARKER in path.read_text(encoding="utf-8", errors="ignore")
)


def run_scanner(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(RUNTIME), *args],
        text=True,
        capture_output=True,
    )


def test_runtime_reports_typed_matches_and_exit_codes(tmp_path: Path):
    scan = tmp_path / "scan"
    logs = tmp_path / "logs"
    out = tmp_path / "out"
    scan.mkdir()
    logs.mkdir()
    payload = b"package: demo@1.2.3\nprocess: suspicious-worker\n"
    (scan / "package-lock.json").write_bytes(payload)
    (scan / "setup.mjs").write_text("marker", encoding="utf-8")
    (logs / "edr.log").write_text("suspicious-worker connected", encoding="utf-8")
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        "packages": ["demo"],
        "package_versions": ["demo@1.2.3"],
        "files": ["setup.mjs"],
        "hashes": [hashlib.sha256(payload).hexdigest()],
        "process_patterns": ["suspicious-worker"],
        "network_patterns": ["connected"],
    }), encoding="utf-8")

    result = run_scanner(tmp_path, str(scan), str(logs), str(out), "--profile", str(profile))

    assert result.returncode == 1
    data = json.loads((out / "scope-results.json").read_text())
    categories = {match["category"] for match in data["matches"]}
    assert {"package", "path", "hash", "process", "network"} <= categories
    assert (out / "selector-inventory.json").exists()


def test_runtime_is_clean_and_excludes_its_output(tmp_path: Path):
    scan = tmp_path / "scan"
    out = tmp_path / "out"
    scan.mkdir()
    out.mkdir()
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"files": ["marker.txt"]}), encoding="utf-8")
    (out / "marker.txt").write_text("marker.txt", encoding="utf-8")

    result = run_scanner(tmp_path, str(scan), "--out", str(out), "--profile", str(profile))

    assert result.returncode == 0
    data = json.loads((out / "scope-results.json").read_text())
    assert data["matches"] == []


def test_runtime_rejects_invalid_scan_root(tmp_path: Path):
    result = run_scanner(tmp_path, str(tmp_path / "missing"))
    assert result.returncode == 2


@pytest.mark.parametrize("wrapper", WRAPPERS, ids=lambda path: path.parent.parent.name)
def test_generated_wrapper_profile_and_clean_scan(wrapper: Path, tmp_path: Path):
    folder = wrapper.parent.parent
    spec = importlib.util.spec_from_file_location(f"hp_wrapper_{folder.name}", wrapper)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    expected = {key: values for key, values in profile_for(folder).items() if values}
    assert module.PROFILE == expected

    scan = tmp_path / "scan"
    out = tmp_path / "out"
    scan.mkdir()
    result = subprocess.run(
        [sys.executable, str(wrapper), str(scan), "--out", str(out)],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    inventory = json.loads((out / "selector-inventory.json").read_text(encoding="utf-8"))
    assert inventory == expected
