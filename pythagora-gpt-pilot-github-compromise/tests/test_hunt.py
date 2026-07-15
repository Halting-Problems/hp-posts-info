#!/usr/bin/env python3
"""Tests for the Pythagora gpt-pilot GitHub compromise hunt packet."""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

FOLDER = Path(__file__).resolve().parent.parent
SCRIPT = FOLDER / "scripts" / "local_repository_and_exported_telemetry_scope.py"
IOCS_JSON = FOLDER / "iocs.json"
FIXTURES = FOLDER / "fixtures"


def _load_script_source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _parse_script() -> ast.Module:
    return ast.parse(_load_script_source(), filename=str(SCRIPT))


def _extract_list_constant(tree: ast.Module, name: str) -> list[str] | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name and isinstance(node.value, ast.List):
                    values: list[str] = []
                    for element in node.value.elts:
                        if isinstance(element, ast.Constant) and isinstance(element.value, str):
                            values.append(element.value)
                    return values
    return None


def _load_iocs() -> dict:
    return json.loads(IOCS_JSON.read_text(encoding="utf-8"))


def _copy_fixture_tree(source: Path, target: Path) -> None:
    shutil.copytree(source, target)


def _run_scan(scan_dir: Path, out_dir: Path, log_root: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "OUT": str(out_dir)}
    if log_root is not None:
        env["LOG_ROOT"] = str(log_root)
    else:
        env.pop("LOG_ROOT", None)
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(scan_dir)],
        cwd=FOLDER,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


@pytest.fixture(scope="module")
def script_tree() -> ast.Module:
    return _parse_script()


@pytest.fixture(scope="module")
def iocs() -> dict:
    return _load_iocs()


def test_script_exists() -> None:
    assert SCRIPT.exists(), f"Missing script: {SCRIPT}"


def test_iocs_json_exists() -> None:
    assert IOCS_JSON.exists(), f"Missing IOC file: {IOCS_JSON}"


def test_script_has_valid_python() -> None:
    ast.parse(_load_script_source(), filename=str(SCRIPT))


def test_script_has_shebang() -> None:
    assert _load_script_source().splitlines()[0].startswith("#!")


def test_script_constants_match_iocs(script_tree: ast.Module, iocs: dict) -> None:
    assert sorted(_extract_list_constant(script_tree, "FILES") or []) == sorted(iocs["iocs"]["files"])
    assert sorted(_extract_list_constant(script_tree, "HASHES") or []) == sorted(iocs["iocs"]["hashes"])
    assert sorted(_extract_list_constant(script_tree, "PROCESS_PATTERNS") or []) == sorted(iocs["iocs"]["process_patterns"])
    assert sorted(_extract_list_constant(script_tree, "NETWORK_PATTERNS") or []) == sorted(iocs["iocs"]["network_patterns"])


def test_clean_fixture_produces_no_hits(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    out_dir = tmp_path / "out"
    _copy_fixture_tree(FIXTURES / "clean", scan_dir)
    result = _run_scan(scan_dir, out_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (out_dir / "repository-indicator-matches.txt").exists()
    assert not (out_dir / "exported-telemetry-indicator-matches.txt").exists()
    indicators = (out_dir / "indicators.txt").read_text(encoding="utf-8")
    assert "Pythagora-io/gpt-pilot" in indicators


def test_repo_fixture_detects_commit_and_files(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    out_dir = tmp_path / "out"
    _copy_fixture_tree(FIXTURES / "repo-hits", scan_dir)
    result = _run_scan(scan_dir, out_dir)
    assert result.returncode == 1, result.stdout + result.stderr
    matches = (out_dir / "repository-indicator-matches.txt").read_text(encoding="utf-8")
    assert "Pythagora-io/gpt-pilot" in matches
    assert "_runtime.bin" in matches


def test_log_fixture_detects_ci_failure_markers(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    log_dir = tmp_path / "logs"
    out_dir = tmp_path / "out"
    _copy_fixture_tree(FIXTURES / "clean", scan_dir)
    _copy_fixture_tree(FIXTURES / "log-hits", log_dir)
    result = _run_scan(scan_dir, out_dir, log_root=log_dir)
    assert result.returncode == 1, result.stdout + result.stderr
    matches = (out_dir / "exported-telemetry-indicator-matches.txt").read_text(encoding="utf-8")
    assert "ruff format --check" in matches
    assert "ruff check" in matches
    assert "I001" in matches
