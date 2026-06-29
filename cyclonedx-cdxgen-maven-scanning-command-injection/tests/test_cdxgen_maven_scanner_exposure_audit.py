from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

FOLDER = Path(__file__).resolve().parent.parent
SCRIPT = FOLDER / "scripts" / "cdxgen_maven_scanner_exposure_audit.py"


def run_script(scan_root: Path, out_dir: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["OUT"] = str(out_dir)
    return subprocess.run(
        ["python3", str(SCRIPT), str(scan_root)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )


def test_clean_repository_returns_zero(tmp_path: Path) -> None:
    scan_root = tmp_path / "repo"
    scan_root.mkdir()
    (scan_root / "package.json").write_text('{"devDependencies":{"@cyclonedx/cdxgen":"12.4.3"}}', encoding="utf-8")
    result = run_script(scan_root, tmp_path / "out")
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "clean"


def test_vulnerable_lockfile_returns_alert(tmp_path: Path) -> None:
    scan_root = tmp_path / "repo"
    scan_root.mkdir()
    (scan_root / "package.json").write_text('{"devDependencies":{"@cyclonedx/cdxgen":"12.4.2"}}', encoding="utf-8")
    result = run_script(scan_root, tmp_path / "out")
    assert result.returncode == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "alert"
    findings_path = Path(payload["output"])
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    assert findings["advisory"] == "GHSA-5vwr-qchf-q4pf"
    assert findings["affected_package"] == "@cyclonedx/cdxgen"
    assert any(item["evidence"] == "12.4.2" for item in findings["findings"])


def test_maven_scanner_workflow_reference_returns_alert(tmp_path: Path) -> None:
    scan_root = tmp_path / "repo"
    workflow_dir = scan_root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "sbom.yml").write_text("run: cdxgen --type maven .\n", encoding="utf-8")
    result = run_script(scan_root, tmp_path / "out")
    assert result.returncode == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["findings"] >= 1


def test_missing_scan_root_returns_collection_failure(tmp_path: Path) -> None:
    result = run_script(tmp_path / "missing", tmp_path / "out")
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
