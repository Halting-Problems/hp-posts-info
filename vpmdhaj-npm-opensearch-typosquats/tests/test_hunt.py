#!/usr/bin/env python3
"""
Auto-generated per-folder tests for: vpmdhaj-npm-opensearch-typosquats

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
    assert "hp-vpmdhaj-npm-opensearch-typosquats-scope" in _load_script_source(), (
        "OUT default does not include 'hp-vpmdhaj-npm-opensearch-typosquats-scope'"
    )


def test_script_domains_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.DOMAINS constant must match iocs.json iocs.domains."""
    expected = sorted(['aab.sportsontheweb.net', 'www.sportsontheweb.net'])
    if not expected:
        pytest.skip("No DOMAINS values in iocs.json")
    actual = _extract_list_constant(script_tree, "DOMAINS")
    assert actual is not None, "Script missing DOMAINS constant but iocs.json has values"
    assert sorted(actual) == expected, (
        f"{DOMAINS} mismatch:\n  script: {sorted(actual)}\n  iocs.json: {expected}"
    )

def test_script_hashes_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.HASHES constant must match iocs.json iocs.hashes."""
    expected = sorted(['a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145', '9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf'])
    if not expected:
        pytest.skip("No HASHES values in iocs.json")
    actual = _extract_list_constant(script_tree, "HASHES")
    assert actual is not None, "Script missing HASHES constant but iocs.json has values"
    assert sorted(actual) == expected, (
        f"{HASHES} mismatch:\n  script: {sorted(actual)}\n  iocs.json: {expected}"
    )

def test_script_packages_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.PACKAGES constant must match iocs.json affected_assets.packages."""
    expected = sorted(['@vpmdhaj/devops-tools', '@vpmdhaj/elastic-helper', '@vpmdhaj/opensearch-setup', '@vpmdhaj/search-setup', 'app-config-utility', 'elastic-opensearch-helper', 'env-config-manager', 'opensearch-config-utility', 'opensearch-security-scanner', 'opensearch-setup', 'opensearch-setup-tool', 'search-cluster-setup', 'search-engine-setup', 'vpmdhaj-opensearch-setup', '@vpmdhaj/aws-compat', '@vpmdhaj/aws-credential-provider-env', '@vpmdhaj/aws-credential-provider-http', '@vpmdhaj/aws-sdk-client-opensearch', '@vpmdhaj/aws-sdk-client-sts', '@vpmdhaj/aws-sdk-credential-provider-node', '@vpmdhaj/aws-sdk-types', '@vpmdhaj/bun', '@vpmdhaj/opensearch', '@vpmdhaj/opensearch-project', '@vpmdhaj/opensearch-js', '@vpmdhaj/sts-client'])
    if not expected:
        pytest.skip("No PACKAGES values in iocs.json")
    actual = _extract_list_constant(script_tree, "PACKAGES")
    assert actual is not None, "Script missing PACKAGES constant but iocs.json has values"
    assert sorted(actual) == expected, (
        f"{PACKAGES} mismatch:\n  script: {sorted(actual)}\n  iocs.json: {expected}"
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


def test_detects_aab_sportsontheweb_net_in_directory(tmp_path):
    """Script must detect indicator 'aab.sportsontheweb.net' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('aab.sportsontheweb.net', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'aab.sportsontheweb.net' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_www_sportsontheweb_net_in_directory(tmp_path):
    """Script must detect indicator 'www.sportsontheweb.net' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('www.sportsontheweb.net', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'www.sportsontheweb.net' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_a39155771e93e65b05195c8a705dfc03aa85c2ec_in_directory(tmp_path):
    """Script must detect indicator 'a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_9d962ed605bb4a39991f8fab9b1d2e423ea4d545_in_directory(tmp_path):
    """Script must detect indicator '9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator '9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf' in hit.txt; "
        f"matches={result['matched']}"
    )
