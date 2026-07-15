#!/usr/bin/env python3
"""Tests for the buffer-utilities campaign hunt script."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "buffer_utilities_campaign_scope.py"
IOCS = ROOT / "iocs.json"
FIXTURES = ROOT / "fixtures"
PACKUMENT_FIXTURE = FIXTURES / "packument" / "buffer-utilities.json"
CLEAN_FIXTURE = FIXTURES / "clean"
DIRTY_FIXTURE = FIXTURES / "dirty"


def _script_source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _tree() -> ast.Module:
    return ast.parse(_script_source(), filename=str(SCRIPT))


def _extract_list(tree: ast.Module, name: str) -> list[str]:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name and isinstance(node.value, ast.List):
                    values: list[str] = []
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            values.append(elt.value)
                    return values
    raise AssertionError(f"missing list constant: {name}")


def _run_script(root: Path, out_dir: Path, packument: Path | None = None) -> dict:
    args = [sys.executable, str(SCRIPT), str(root), "--out", str(out_dir)]
    if packument is not None:
        args.extend(["--packument", str(packument)])
    completed = subprocess.run(args, capture_output=True, text=True, check=False)
    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    report["stdout"] = completed.stdout
    report["stderr"] = completed.stderr
    return report


@pytest.fixture(scope="module")
def iocs() -> dict:
    return json.loads(IOCS.read_text(encoding="utf-8"))


def test_script_exists():
    assert SCRIPT.exists(), SCRIPT


def test_script_has_shebang_and_docstring():
    source = _script_source().splitlines()
    assert source[0].startswith("#!")
    assert "buffer-utilities brandjacking campaign" in source[1].lower()


def test_script_syntax():
    ast.parse(_script_source(), filename=str(SCRIPT))


def test_package_family_constants_match_iocs(iocs):
    script_packages = sorted(_extract_list(_tree(), "PACKAGE_FAMILY_NAMES"))
    expected = sorted(iocs["affected_assets"]["packages"])
    assert script_packages == expected


def test_archive_url_constants_match_iocs(iocs):
    script_urls = sorted(_extract_list(_tree(), "ARCHIVE_URLS"))
    expected = sorted(iocs["iocs"]["urls"])
    assert script_urls == expected


def test_loader_marker_constants_include_documented_strings():
    markers = set(_extract_list(_tree(), "LOADER_MARKERS"))
    for needle in ["postinstall", "node setup.cjs --no-warnings", "NODE_TLS_REJECT_UNAUTHORIZED", ".pkg_history", ".pkg_logs", ".vscode"]:
        assert needle in markers


def test_clean_fixture_produces_no_hits(tmp_path):
    scan_root = tmp_path / "clean"
    shutil.copytree(CLEAN_FIXTURE, scan_root)
    out_dir = tmp_path / "out-clean"
    report = _run_script(scan_root, out_dir, PACKUMENT_FIXTURE)
    assert report["scan"]["file_hit_count"] == 0
    assert report["interpretation"]["campaign_match"] is False
    assert report["packument"]["missing_version_objects"] == ["1.0.0", "1.1.0", "1.1.1"]


def test_dirty_fixture_detects_campaign_strings(tmp_path):
    scan_root = tmp_path / "dirty"
    shutil.copytree(DIRTY_FIXTURE, scan_root)
    out_dir = tmp_path / "out-dirty"
    report = _run_script(scan_root, out_dir, PACKUMENT_FIXTURE)
    assert report["scan"]["file_hit_count"] >= 1
    assert "buffer-utilities" in report["scan"]["hit_terms"]
    assert "postinstall" in report["scan"]["hit_terms"]
    assert report["interpretation"]["campaign_match"] is True
    assert report["packument"]["latest"] == "0.0.1-security"


def test_packument_summary_preserves_time_entries(tmp_path):
    report = _run_script(CLEAN_FIXTURE, tmp_path / "out-packument", PACKUMENT_FIXTURE)
    assert report["packument"]["time_entries"]["1.0.0"] == "2026-05-30T08:15:38.814Z"
    assert report["packument"]["time_entries"]["0.0.1-security"] == "2026-06-09T11:48:35.610Z"

