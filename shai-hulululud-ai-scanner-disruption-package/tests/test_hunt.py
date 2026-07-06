#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ioc_scope_scan.py"
IOCS = ROOT / "iocs.json"
FIXTURES = ROOT / "fixtures"


def run_script(scan_root: Path, telemetry_root: Path | None, out_dir: Path) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(SCRIPT), str(scan_root), "--out", str(out_dir)]
    if telemetry_root is not None:
        cmd.extend(["--log-root", str(telemetry_root)])
    return subprocess.run(cmd, text=True, capture_output=True)


def load_iocs() -> dict:
    return json.loads(IOCS.read_text(encoding="utf-8"))


def test_files_exist() -> None:
    assert SCRIPT.exists(), f"missing script: {SCRIPT}"
    assert IOCS.exists(), f"missing iocs.json: {IOCS}"


def test_iocs_contain_expected_selectors() -> None:
    data = load_iocs()
    assert data["affected_assets"]["packages"] == ["shai_hulululud"]
    assert "shai_hulululud@1.0.48596" in data["iocs"]["package_versions"]
    assert "9dcce285116e31a5c8f8e3a4ed596a791e62c3e47185e4ee36c489422b1fbbbc" in data["iocs"]["hashes"]


def test_script_has_required_constants() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "shai_hulululud" in source
    assert "shai_hulululud@1.0.48596" in source
    assert "9dcce285116e31a5c8f8e3a4ed596a791e62c3e47185e4ee36c489422b1fbbbc" in source
    assert "eval(" in source


def test_clean_fixture_produces_no_matches(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = run_script(FIXTURES / "clean", None, out_dir)
    assert result.returncode == 0, result.stderr
    assert "No IOC matches found" in result.stdout
    assert not (out_dir / "ioc-scope-matches.txt").exists()


def test_dirty_fixture_finds_repository_and_telemetry_hits(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = run_script(FIXTURES / "dirty" / "repository", FIXTURES / "dirty" / "telemetry", out_dir)
    assert result.returncode == 1, result.stdout + result.stderr
    matches = (out_dir / "ioc-scope-matches.txt").read_text(encoding="utf-8")
    summary = json.loads((out_dir / "scan-summary.json").read_text(encoding="utf-8"))
    assert "shai_hulululud" in matches
    assert "https://registry.npmjs.org/shai_hulululud/-/shai_hulululud-1.0.48596.tgz" in matches
    assert "9dcce285116e31a5c8f8e3a4ed596a791e62c3e47185e4ee36c489422b1fbbbc" in matches
    assert summary["match_count"] > 0
    assert "summary written" in result.stdout.lower()
