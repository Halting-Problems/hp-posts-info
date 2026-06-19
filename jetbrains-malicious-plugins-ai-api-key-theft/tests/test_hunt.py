#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "jetbrains_malicious_plugins_ai_api_key_theft_scope.py"
IOCS = ROOT / "iocs.json"
FIXTURES = ROOT / "fixtures"


def run_script(scan_root: Path, telemetry_root: Path | None, out_dir: Path) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(SCRIPT), str(scan_root), "--out", str(out_dir)]
    if telemetry_root is not None:
        cmd.extend(["--telemetry-root", str(telemetry_root)])
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


def load_iocs() -> dict:
    return json.loads(IOCS.read_text(encoding="utf-8"))


def test_files_exist() -> None:
    assert SCRIPT.exists(), f"missing script: {SCRIPT}"
    assert IOCS.exists(), f"missing iocs.json: {IOCS}"


def test_iocs_contain_expected_selectors() -> None:
    data = load_iocs()
    plugin_ids = data["affected_assets"]["packages"]
    assert "org.sm.yms.toolkit" in plugin_ids
    assert "39.107.60.51" in data["iocs"]["ips"]
    assert "http://39.107.60.51/api/software/key" in data["iocs"]["urls"]


def test_script_has_required_constants() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "org.sm.yms.toolkit" in source
    assert "39.107.60.51" in source
    assert "F48D2AA7CF341F782C1D" in source


def test_clean_fixture_produces_no_matches(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = run_script(FIXTURES / "clean", None, out_dir)
    assert "Repository matches: 0" in result.stdout
    assert not (out_dir / "repository-indicator-matches.txt").exists()


def test_dirty_fixture_finds_repository_and_telemetry_hits(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = run_script(FIXTURES / "dirty" / "repository", FIXTURES / "dirty" / "telemetry", out_dir)
    repo_matches = (out_dir / "repository-indicator-matches.txt").read_text(encoding="utf-8")
    telemetry_matches = (out_dir / "exported-telemetry-indicator-matches.txt").read_text(encoding="utf-8")
    summary = json.loads((out_dir / "scan-summary.json").read_text(encoding="utf-8"))

    assert "org.sm.yms.toolkit" in repo_matches
    assert "39.107.60.51" in telemetry_matches
    assert summary["repository_match_count"] > 0
    assert summary["telemetry_match_count"] > 0
    assert "Summary written to" in result.stdout
