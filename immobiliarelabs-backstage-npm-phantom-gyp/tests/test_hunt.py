import json
import os
import subprocess
import sys
from pathlib import Path

FOLDER = Path(__file__).resolve().parent.parent
SCRIPT = FOLDER / "scripts" / "immobiliarelabs_backstage_scope.py"
IOCS = FOLDER / "iocs.json"


def run_scan(root: Path, out: Path, log_root: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["OUT"] = str(out)
    if log_root is not None:
        env["LOG_ROOT"] = str(log_root)
    else:
        env.pop("LOG_ROOT", None)
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(root)],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def test_script_has_valid_syntax():
    compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec")


def test_iocs_are_embedded_in_script():
    source = SCRIPT.read_text(encoding="utf-8")
    iocs = json.loads(IOCS.read_text(encoding="utf-8"))
    for package in iocs["affected_assets"]["packages"]:
        assert package in source
    for package_version in iocs["iocs"]["package_versions"]:
        assert package_version in source
    for digest in iocs["iocs"]["hashes"]:
        assert digest in source
    for file_name in iocs["iocs"]["files"]:
        assert file_name in source


def test_dirty_fixture_alerts(tmp_path):
    out = tmp_path / "out"
    result = run_scan(FOLDER / "fixtures" / "dirty", out)
    assert result.returncode == 1, result.stdout + result.stderr
    data = json.loads((out / "scope-results.json").read_text(encoding="utf-8"))
    indicators = {match["indicator"] for match in data["matches"]}
    assert "@immobiliarelabs/backstage-plugin-gitlab@2.1.2" in indicators


def test_clean_fixture_returns_zero(tmp_path):
    out = tmp_path / "out"
    result = run_scan(FOLDER / "fixtures" / "clean", out)
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads((out / "scope-results.json").read_text(encoding="utf-8"))
    assert data["match_count"] == 0


def test_log_root_catches_execution_patterns(tmp_path):
    out = tmp_path / "out"
    result = run_scan(FOLDER / "fixtures" / "clean", out, FOLDER / "fixtures" / "logs")
    assert result.returncode == 1, result.stdout + result.stderr
    data = json.loads((out / "scope-results.json").read_text(encoding="utf-8"))
    indicators = {match["indicator"] for match in data["matches"]}
    assert "@immobiliarelabs/backstage-plugin-gitlab@2.1.2" in indicators
    assert "node-gyp rebuild" in indicators
    assert "node index.js" in indicators
