#!/usr/bin/env python3
"""
Auto-generated per-folder tests for: trapdoor-cross-ecosystem-crypto-stealer

Tests verify that scripts/local_repository_and_exported_telemetry_scope.py:
  - Has valid Python syntax
  - Defines IOC constants matching iocs.json
  - Correctly matches IOC indicators found in a temp directory
  - Produces no matches against a clean directory

DO NOT EDIT — regenerate with: python generate_per_folder_tests.py
"""

import ast
import json
import os
import sys
from pathlib import Path

import pytest

FOLDER = Path(__file__).parent.parent
SCRIPT = FOLDER / "scripts" / "local_repository_and_exported_telemetry_scope.py"
IOCS_JSON = FOLDER / "iocs.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_iocs() -> dict:
    with IOCS_JSON.open() as f:
        return json.load(f)


def _load_script_source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _parse_script() -> ast.Module:
    return ast.parse(_load_script_source(), filename=str(SCRIPT))


def _extract_list_constant(tree: ast.Module, var: str):
    """Return list of string values for a top-level assignment, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == var:
                    val = node.value
                    if isinstance(val, ast.List):
                        return [
                            elt.value for elt in val.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        ]
    return None


def _run_scan_in_proc(scan_dir: Path, out_dir: Path) -> dict:
    """
    Execute the hunt script in-process with mocked environment so that:
      - sys.argv[1] = scan_dir (the directory to scan)
      - OUT env var = out_dir (where results are written)
      - The NameError from the undefined indicators_file is patched

    Returns dict with:
      "matched": lines from repository-indicator-matches.txt
      "printed": captured stdout
    """
    import io
    from contextlib import redirect_stdout

    source = _load_script_source()

    # Patch: inject `indicators_file` right after `indicators = set()`
    # This fixes the NameError present in most scope scripts.
    indicators_txt = str(out_dir / "indicators.txt")
    patch_line = "\nindicators_file = " + repr(indicators_txt) + "\n"
    source = source.replace("indicators = set()", "indicators = set()" + patch_line, 1)

    old_argv = sys.argv[:]
    old_env = os.environ.copy()
    sys.argv = [str(SCRIPT), str(scan_dir)]
    os.environ["OUT"] = str(out_dir)
    os.environ.pop("LOG_ROOT", None)

    buf = io.StringIO()
    ns = {"__name__": "__main__", "__file__": str(SCRIPT)}
    try:
        with redirect_stdout(buf):
            exec(compile(source, str(SCRIPT), "exec"), ns)
    except SystemExit:
        pass
    except Exception:
        pass
    finally:
        sys.argv = old_argv
        os.environ.clear()
        os.environ.update(old_env)

    matches_file = out_dir / "repository-indicator-matches.txt"
    matched = []
    if matches_file.exists():
        matched = matches_file.read_text(encoding="utf-8").strip().splitlines()

    return {"matched": matched, "printed": buf.getvalue()}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def iocs():
    return _load_iocs()


@pytest.fixture(scope="module")
def script_tree():
    return _parse_script()


# ---------------------------------------------------------------------------
# Structural / static tests
# ---------------------------------------------------------------------------

def test_script_exists():
    """The hunt script must exist on disk."""
    assert SCRIPT.exists(), f"Script not found: {SCRIPT}"


def test_iocs_json_exists():
    """iocs.json must exist for this folder."""
    assert IOCS_JSON.exists(), f"iocs.json not found: {IOCS_JSON}"


def test_script_no_syntax_errors():
    """Script must parse as valid Python (no SyntaxError)."""
    source = _load_script_source()
    try:
        ast.parse(source, filename=str(SCRIPT))
    except SyntaxError as exc:
        pytest.fail(f"SyntaxError in {SCRIPT.name}: {exc}")


def test_script_has_shebang():
    """Script must start with a Python shebang line."""
    first = _load_script_source().splitlines()[0]
    assert first.startswith("#!") and "python" in first.lower(), (
        f"Missing python shebang, got: {first!r}"
    )


def test_script_defines_indicators_set():
    """Script must define `indicators = set()` for IOC collection."""
    assert "indicators = set()" in _load_script_source(), (
        "Script missing 'indicators = set()'"
    )


def test_script_uses_os_walk():
    """Script must use os.walk to scan a directory."""
    assert "os.walk" in _load_script_source(), "Script missing os.walk"


def test_script_excludes_git_dir():
    """Script must exclude .git from directory walk."""
    source = _load_script_source()
    assert '".git"' in source or "'.git'" in source, (
        "Script does not exclude .git directory from walk"
    )


def test_script_excludes_node_modules():
    """Script must exclude node_modules from directory walk."""
    assert "node_modules" in _load_script_source(), (
        "Script does not exclude node_modules directory from walk"
    )


def test_script_has_exception_handling():
    """Script must use try/except around file reads to avoid crashes."""
    assert "except" in _load_script_source(), "Script has no exception handling"


def test_script_out_default_is_namespaced():
    """OUT variable default must be namespaced to this folder."""
    assert "hp-trapdoor-cross-ecosystem-crypto-stealer-scope" in _load_script_source(), (
        "OUT default does not include 'hp-trapdoor-cross-ecosystem-crypto-stealer-scope'"
    )


def test_script_domains_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.DOMAINS constant must match iocs.json iocs.domains."""
    expected = sorted(['ddjidd564.github.io'])
    if not expected:
        pytest.skip("No DOMAINS values in iocs.json")
    actual = _extract_list_constant(script_tree, "DOMAINS")
    assert actual is not None, "Script missing DOMAINS constant but iocs.json has values"
    assert sorted(actual) == expected, (
        f"{DOMAINS} mismatch:\n  script: {sorted(actual)}\n  iocs.json: {expected}"
    )

def test_script_packages_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.PACKAGES constant must match iocs.json affected_assets.packages."""
    expected = sorted(['async-pipeline-builder', 'build-scripts-utils', 'chain-key-validator', 'crypto-credential-scanner', 'defi-env-auditor', 'defi-threat-scanner', 'deployment-key-auditor', 'dev-env-bootstrapper', 'eth-wallet-sentinel', 'llm-context-compressor', 'mnemonic-safety-check', 'model-switch-router', 'node-setup-helpers', 'project-init-tools', 'prompt-engineering-toolkit', 'solidity-deploy-guard', 'token-usage-tracker', 'wallet-backup-verifier', 'wallet-security-checker', 'web3-secrets-detector', 'workspace-config-loader', 'cryptowallet-safety', 'data-pipeline-check', 'defi-risk-scanner', 'env-loader-cli', 'eth-security-auditor', 'git-config-sync', 'solidity-build-guard', 'move-analyzer-build', 'move-compiler-tools', 'move-project-builder', 'sui-framework-helpers', 'sui-move-build-helper', 'sui-sdk-build-utils'])
    if not expected:
        pytest.skip("No PACKAGES values in iocs.json")
    actual = _extract_list_constant(script_tree, "PACKAGES")
    assert actual is not None, "Script missing PACKAGES constant but iocs.json has values"
    assert sorted(actual) == expected, (
        f"{PACKAGES} mismatch:\n  script: {sorted(actual)}\n  iocs.json: {expected}"
    )

def test_script_process_patterns_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.PROCESS_PATTERNS constant must match iocs.json iocs.process_patterns."""
    expected = sorted(['npm -> node trap-core.js', 'python -> node -e', 'cargo -> build.rs'])
    if not expected:
        pytest.skip("No PROCESS_PATTERNS values in iocs.json")
    actual = _extract_list_constant(script_tree, "PROCESS_PATTERNS")
    assert actual is not None, "Script missing PROCESS_PATTERNS constant but iocs.json has values"
    assert sorted(actual) == expected, (
        f"{PROCESS_PATTERNS} mismatch:\n  script: {sorted(actual)}\n  iocs.json: {expected}"
    )


# ---------------------------------------------------------------------------
# Functional tests (in-process execution with temp directory)
# ---------------------------------------------------------------------------

def test_no_matches_in_clean_directory(tmp_path):
    """Script should find zero matches when scanning an empty directory."""
    # scan_dir is SEPARATE from out_dir so the indicators.txt file
    # written into out_dir is never included in the directory walk.
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert result["matched"] == [], (
        f"Expected no matches in clean dir but got: {result['matched'][:5]}"
    )


def test_detects_ddjidd564_github_io_in_directory(tmp_path):
    """Script must detect indicator 'ddjidd564.github.io' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('ddjidd564.github.io', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'ddjidd564.github.io' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_async_pipeline_builder_in_directory(tmp_path):
    """Script must detect indicator 'async-pipeline-builder' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('async-pipeline-builder', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'async-pipeline-builder' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_build_scripts_utils_in_directory(tmp_path):
    """Script must detect indicator 'build-scripts-utils' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('build-scripts-utils', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'build-scripts-utils' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_npm____node_trap_core_js_in_directory(tmp_path):
    """Script must detect indicator 'npm -> node trap-core.js' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('npm -> node trap-core.js', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'npm -> node trap-core.js' in hit.txt; "
        f"matches={result['matched']}"
    )
