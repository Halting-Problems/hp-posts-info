#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

FOLDER = Path(__file__).resolve().parent.parent
SCRIPT = FOLDER / "scripts" / "npm_dependency_confusion_developer_profiling_scope.py"
IOCS = FOLDER / "iocs.json"
CLEAN_FIXTURE = FOLDER / "fixtures" / "clean"
DIRTY_FIXTURE = FOLDER / "fixtures" / "dirty"


def load_module():
    spec = importlib.util.spec_from_file_location("npm_dependency_confusion_developer_profiling_scope", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_iocs() -> dict:
    return json.loads(IOCS.read_text(encoding="utf-8"))


def test_script_exists():
    assert SCRIPT.exists()


def test_iocs_exists():
    assert IOCS.exists()


def test_script_parses():
    import ast

    ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))


def test_iocs_package_versions_match_script():
    module = load_module()
    iocs = load_iocs()
    assert sorted(module.PACKAGE_VERSIONS) == sorted(iocs["iocs"]["package_versions"])


def test_iocs_packages_are_canonical_and_unversioned():
    iocs = load_iocs()
    packages = iocs["affected_assets"]["packages"]
    assert all("@0.0.1-security" not in package for package in packages)
    assert "@cloudplatform-single-spa/logaas" in packages
    assert "@capibar.chat/ui-kit" in packages
    assert "@sber-ecom-core/sberpay-widget" in packages


def test_clean_fixture_returns_no_findings():
    module = load_module()
    findings = module.scan_paths([CLEAN_FIXTURE])
    assert findings == []


def test_dirty_fixture_matches_key_indicators():
    module = load_module()
    findings = module.scan_paths([DIRTY_FIXTURE])
    indicators = {finding.indicator for finding in findings}
    assert "@cloudplatform-single-spa/logaas@0.0.1-security" in indicators
    assert "@capibar.chat/ui-kit@0.0.1-security" in indicators
    assert "@sber-ecom-core/sberpay-widget@0.0.1-security" in indicators
    assert "oob.moika.tech" in indicators
    assert "X-Secret" in indicators
    assert "RECON_ONLY" in indicators
    assert "postinstall" in indicators


def test_cli_returns_positive_exit_on_dirty_fixture(tmp_path):
    report_path = tmp_path / "report.json"
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(DIRTY_FIXTURE), "--output", str(report_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert report_path.exists()
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["finding_count"] > 0
    assert any(item["indicator"] == "oob.moika.tech" for item in payload["findings"])


def test_cli_returns_zero_exit_on_clean_fixture():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(CLEAN_FIXTURE)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "No Microsoft-tracked dependency-confusion indicators found." in completed.stdout
