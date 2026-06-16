from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FOLDER = Path(__file__).resolve().parent.parent
SCRIPT = FOLDER / "scripts" / "checkout_and_log_scope.py"
FIXTURES = FOLDER / "fixtures"


def run_scan(target: Path, *extra_args: str):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *extra_args, str(target)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_script_syntax():
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_clean_checkout_fixture_is_clean():
    result = run_scan(FIXTURES / "clean_checkout")
    assert result.returncode == 0
    assert "no Claude Code GitHub Action exposure indicators found" in result.stdout


def test_dirty_checkout_fixture_flags_all_core_indicators():
    result = run_scan(FIXTURES / "dirty_checkout")
    assert result.returncode == 1
    stdout = result.stdout
    assert "action_reference" in stdout
    assert "version_boundary" in stdout
    assert "workflow_secret" in stdout
    assert "readable_env_path" in stdout


def test_clean_log_export_fixture_is_clean():
    result = run_scan(FIXTURES / "clean_log_export.txt")
    assert result.returncode == 0


def test_dirty_log_export_fixture_flags_indicator_export():
    result = run_scan(FIXTURES / "dirty_log_export.txt")
    assert result.returncode == 1
    stdout = result.stdout
    assert "anthropics/claude-code" in stdout
    assert "ANTHROPIC_API_KEY" in stdout
    assert "/proc/self/environ" in stdout
