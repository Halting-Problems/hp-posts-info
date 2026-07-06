from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "local_repository_and_exported_telemetry_scope.py"
FIXTURES = ROOT / "fixtures"
IOCS = ROOT / "iocs.json"


def run_hunt(target: Path, out_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(target), "--out", str(out_dir)],
        capture_output=True,
        text=True,
        check=False,
    )


def load_indicators() -> dict:
    return json.loads(IOCS.read_text(encoding="utf-8"))


def test_script_syntax_and_indicator_inventory() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    compile(source, str(SCRIPT), "exec")
    assert "DEFAULT_EXCLUDES" in source
    assert "scan-summary.json" in source


def test_clean_fixture_returns_zero(tmp_path: Path) -> None:
    out_dir = tmp_path / "clean-out"
    result = run_hunt(FIXTURES / "clean", out_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads((out_dir / "scan-summary.json").read_text(encoding="utf-8"))
    assert summary["match_count"] == 0
    assert not (out_dir / "repository-indicator-matches.txt").exists()


def test_positive_fixture_finds_expected_hits(tmp_path: Path) -> None:
    out_dir = tmp_path / "positive-out"
    result = run_hunt(FIXTURES / "positive", out_dir)
    assert result.returncode == 1, result.stdout + result.stderr
    summary = json.loads((out_dir / "scan-summary.json").read_text(encoding="utf-8"))
    assert summary["match_count"] > 0
    indicators = {item["indicator"] for item in summary["matches"]}
    assert "easy-day-js@1.11.22" in indicators
    assert "setup.cjs" in indicators
    assert "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf" in indicators


def test_helper_functions_detect_literals() -> None:
    spec = importlib.util.spec_from_file_location(
        "mastra_hunt",
        SCRIPT,
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    indicators = module.build_indicators(module.load_iocs(IOCS))
    hits = module.scan_text(
        Path("sample.log"),
        "easy-day-js@1.11.22 setup.cjs https://23.254.164.92:8000/update/49890878",
        indicators,
    )
    assert any(hit["indicator"] == "easy-day-js@1.11.22" for hit in hits)
    assert any(hit["indicator"] == "setup.cjs" for hit in hits)


@pytest.mark.parametrize("missing", [Path("/nonexistent/path/for/mastra")])
def test_missing_root_returns_two(missing: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(missing)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "directory not found" in result.stderr
