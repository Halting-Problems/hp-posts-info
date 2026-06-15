#!/usr/bin/env python3
"""
Auto-generated per-folder tests for: redhat-cloud-services-npm-miasma-compromise

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
    assert "hp-redhat-cloud-services-npm-miasma-compromise-scope" in _load_script_source(), (
        "OUT default does not include 'hp-redhat-cloud-services-npm-miasma-compromise-scope'"
    )


def test_script_domains_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.DOMAINS constant must match iocs.json iocs.domains."""
    expected = sorted(['registry.npmjs.org', 'api.github.com', 'github.com'])
    if not expected:
        pytest.skip("No DOMAINS values in iocs.json")
    actual = _extract_list_constant(script_tree, "DOMAINS")
    assert actual is not None, "Script missing DOMAINS constant but iocs.json has values"
    assert sorted(actual) == expected, (
        f"{DOMAINS} mismatch:\n  script: {sorted(actual)}\n  iocs.json: {expected}"
    )

def test_script_packages_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.PACKAGES constant must match iocs.json affected_assets.packages."""
    expected = sorted(['@redhat-cloud-services/patch-client@4.0.4', '@redhat-cloud-services/insights-client@3.0.3', '@redhat-cloud-services/host-inventory-client@2.0.4', '@redhat-cloud-services/vulnerabilities-client@2.0.3', '@redhat-cloud-services/vulnerabilities-client@2.0.4', '@redhat-cloud-services/remediations-client@4.0.3', '@redhat-cloud-services/sources-client@3.0.4', '@redhat-cloud-services/compliance-client@3.0.4', '@redhat-cloud-services/rbac-client@2.0.3', '@redhat-cloud-services/advisor-client@4.0.3', '@redhat-cloud-services/notifications-client@3.0.3', '@redhat-cloud-services/integrations-client@2.0.4', '@redhat-cloud-services/drift-client@3.0.3', '@redhat-cloud-services/content-sources-client@4.0.4', '@redhat-cloud-services/approval-client@2.0.3', '@redhat-cloud-services/topms-client@2.0.4', '@redhat-cloud-services/ros-client@2.0.4', '@redhat-cloud-services/cost-management-client@3.0.4', '@redhat-cloud-services/subscriptions-client@3.0.4', '@redhat-cloud-services/swatch-client@2.0.3', '@redhat-cloud-services/image-builder-client@3.0.3', '@redhat-cloud-services/vulnerability-client@2.0.4', '@redhat-cloud-services/provisioning-client@2.0.3', '@redhat-cloud-services/patch-advisory-client@2.0.3', '@redhat-cloud-services/quickstarts-client@2.0.3', '@redhat-cloud-services/notifications-backend-client@2.0.4', '@redhat-cloud-services/landing-page-frontend@2.0.3', '@redhat-cloud-services/frontend-components@6.0.4', '@redhat-cloud-services/frontend-components-utilities@4.0.4', '@redhat-cloud-services/frontend-components-notifications@3.0.4'])
    if not expected:
        pytest.skip("No PACKAGES values in iocs.json")
    actual = _extract_list_constant(script_tree, "PACKAGES")
    assert actual is not None, "Script missing PACKAGES constant but iocs.json has values"
    assert sorted(actual) == expected, (
        f"{PACKAGES} mismatch:\n  script: {sorted(actual)}\n  iocs.json: {expected}"
    )

def test_script_process_patterns_constant_matches_iocs(script_tree, iocs):
    """SCRIPT.PROCESS_PATTERNS constant must match iocs.json iocs.process_patterns."""
    expected = sorted(['npm install executing lifecycle script from @redhat-cloud-services package', 'node or bun process launched from package lifecycle hook', 'workflow run using id-token: write and npm trusted publishing'])
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


def test_detects_registry_npmjs_org_in_directory(tmp_path):
    """Script must detect indicator 'registry.npmjs.org' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('registry.npmjs.org', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'registry.npmjs.org' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_api_github_com_in_directory(tmp_path):
    """Script must detect indicator 'api.github.com' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('api.github.com', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator 'api.github.com' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_redhat_cloud_services_patch_client_4_0_in_directory(tmp_path):
    """Script must detect indicator '@redhat-cloud-services/patch-client@4.0.4' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('@redhat-cloud-services/patch-client@4.0.4', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator '@redhat-cloud-services/patch-client@4.0.4' in hit.txt; "
        f"matches={result['matched']}"
    )

def test_detects_redhat_cloud_services_insights_client_3_in_directory(tmp_path):
    """Script must detect indicator '@redhat-cloud-services/insights-client@3.0.3' when present in a scanned file."""
    scan_dir = tmp_path / 'scan'
    scan_dir.mkdir()
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    hit_file = scan_dir / 'hit.txt'
    hit_file.write_text('@redhat-cloud-services/insights-client@3.0.3', encoding='utf-8', errors='replace')
    result = _run_scan_in_proc(scan_dir, out_dir)
    assert len(result['matched']) >= 1, (
        f"Script failed to detect indicator '@redhat-cloud-services/insights-client@3.0.3' in hit.txt; "
        f"matches={result['matched']}"
    )
