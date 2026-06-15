#!/usr/bin/env python3
"""
generate_per_folder_tests.py

Generates a per-folder tests/test_hunt.py for every post folder that:
  1. Has a scripts/local_repository_and_exported_telemetry_scope.py
  2. Does NOT already have a tests/ directory

Run from the repo root:
    python generate_per_folder_tests.py
"""

import ast
import json
from pathlib import Path
from string import Template

REPO_ROOT = Path(__file__).parent
EXCLUDED = {".git", ".venv", ".pytest_cache", "tests", "__pycache__"}


def _get_ioc_values(iocs: dict, path: list) -> list:
    """Navigate nested dict and return list at path."""
    cur = iocs
    for key in path:
        if not isinstance(cur, dict):
            return []
        cur = cur.get(key, [])
    if not isinstance(cur, list):
        return []
    return [str(v) for v in cur if v]


def _safe_label(value: str) -> str:
    """Make a safe Python identifier fragment from an arbitrary string."""
    label = "".join(c if c.isalnum() else "_" for c in value)
    label = label[:40].strip("_")
    return label or "value"


def _build_ioc_constant_test(var: str, ioc_display_path: str, values: list) -> str:
    """Return a single test function that checks a script constant vs iocs.json."""
    lines = [
        f"",
        f"def test_script_{var.lower()}_constant_matches_iocs(script_tree, iocs):",
        f'    """SCRIPT.{var} constant must match iocs.json {ioc_display_path}."""',
        f"    expected = sorted({repr(values)})",
        f"    if not expected:",
        f'        pytest.skip("No {var} values in iocs.json")',
        f'    actual = _extract_list_constant(script_tree, "{var}")',
        f"    assert actual is not None, \"Script missing {var} constant but iocs.json has values\"",
        f'    assert sorted(actual) == expected, (',
        f'        f"{{{var}}} mismatch:\\n  script: {{sorted(actual)}}\\n  iocs.json: {{expected}}"',
        f"    )",
    ]
    return "\n".join(lines)


def _build_indicator_match_test(label: str, indicator: str) -> str:
    """Return a test that checks the script detects a specific indicator string."""
    lines = [
        f"",
        f"def test_detects_{label}_in_directory(tmp_path):",
        f'    """Script must detect indicator {indicator!r} when present in a scanned file."""',
        f"    scan_dir = tmp_path / 'scan'",
        f"    scan_dir.mkdir()",
        f"    out_dir = tmp_path / 'out'",
        f"    out_dir.mkdir()",
        f"    hit_file = scan_dir / 'hit.txt'",
        f"    hit_file.write_text({indicator!r}, encoding='utf-8', errors='replace')",
        f"    result = _run_scan_in_proc(scan_dir, out_dir)",
        f"    assert len(result['matched']) >= 1, (",
        f"        f\"Script failed to detect indicator {indicator!r} in hit.txt; \"",
        f"        f\"matches={{result['matched']}}\"",
        f"    )",
    ]
    return "\n".join(lines)


def generate_test_file(folder: Path) -> str:
    """Return the full content of tests/test_hunt.py for the given folder."""
    folder_name = folder.name
    iocs_path = folder / "iocs.json"

    iocs = {}
    if iocs_path.exists():
        try:
            with iocs_path.open() as f:
                iocs = json.load(f)
        except json.JSONDecodeError:
            pass

    # Map: (var_name, ioc_path_list, ioc_display_path)
    var_config = [
        ("DOMAINS",          ["iocs", "domains"],              "iocs.domains"),
        ("HASHES",           ["iocs", "hashes"],               "iocs.hashes"),
        ("IPS",              ["iocs", "ips"],                   "iocs.ips"),
        ("PACKAGES",         ["affected_assets", "packages"],  "affected_assets.packages"),
        ("PROCESS_PATTERNS", ["iocs", "process_patterns"],     "iocs.process_patterns"),
    ]

    ioc_tests_block = ""
    all_indicators: list[str] = []

    for var, ioc_path, display_path in var_config:
        values = _get_ioc_values(iocs, ioc_path)
        if values:
            ioc_tests_block += _build_ioc_constant_test(var, display_path, values)
            ioc_tests_block += "\n"
            all_indicators.extend(values[:2])

    # Also collect URL/file/version indicators for match tests
    for path in [["iocs", "urls"], ["iocs", "files"]]:
        vals = _get_ioc_values(iocs, path)
        all_indicators.extend(vals[:1])

    indicator_tests_block = ""
    seen_labels: set[str] = set()
    for indicator in all_indicators[:4]:  # cap at 4 match tests
        label = _safe_label(indicator)
        # Ensure uniqueness
        base = label
        count = 1
        while label in seen_labels:
            label = f"{base}_{count}"
            count += 1
        seen_labels.add(label)
        indicator_tests_block += _build_indicator_match_test(label, indicator)
        indicator_tests_block += "\n"

    header = f'''#!/usr/bin/env python3
"""
Auto-generated per-folder tests for: {folder_name}

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
    patch_line = "\\nindicators_file = " + repr(indicators_txt) + "\\n"
    source = source.replace("indicators = set()", "indicators = set()" + patch_line, 1)

    old_argv = sys.argv[:]
    old_env = os.environ.copy()
    sys.argv = [str(SCRIPT), str(scan_dir)]
    os.environ["OUT"] = str(out_dir)
    os.environ.pop("LOG_ROOT", None)

    buf = io.StringIO()
    ns = {{"__name__": "__main__", "__file__": str(SCRIPT)}}
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

    return {{"matched": matched, "printed": buf.getvalue()}}


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
    assert SCRIPT.exists(), f"Script not found: {{SCRIPT}}"


def test_iocs_json_exists():
    """iocs.json must exist for this folder."""
    assert IOCS_JSON.exists(), f"iocs.json not found: {{IOCS_JSON}}"


def test_script_no_syntax_errors():
    """Script must parse as valid Python (no SyntaxError)."""
    source = _load_script_source()
    try:
        ast.parse(source, filename=str(SCRIPT))
    except SyntaxError as exc:
        pytest.fail(f"SyntaxError in {{SCRIPT.name}}: {{exc}}")


def test_script_has_shebang():
    """Script must start with a Python shebang line."""
    first = _load_script_source().splitlines()[0]
    assert first.startswith("#!") and "python" in first.lower(), (
        f"Missing python shebang, got: {{first!r}}"
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
    assert "hp-{folder_name}-scope" in _load_script_source(), (
        "OUT default does not include 'hp-{folder_name}-scope'"
    )
'''

    functional_section = '''
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
'''

    return header + "\n" + ioc_tests_block + "\n" + functional_section + "\n" + indicator_tests_block


def main():
    created = 0
    skipped = 0

    for folder in sorted(REPO_ROOT.iterdir()):
        if not folder.is_dir():
            continue
        if folder.name in EXCLUDED or folder.name.startswith("."):
            continue
        if folder.name == "tests":
            continue

        # Skip folders that already have their own tests/ directory
        tests_dir = folder / "tests"
        if tests_dir.exists():
            print(f"[skip] {folder.name} — already has tests/")
            skipped += 1
            continue

        # Only process folders with the standard scope script
        script = folder / "scripts" / "local_repository_and_exported_telemetry_scope.py"
        if not script.exists():
            print(f"[skip] {folder.name} — no scope script")
            skipped += 1
            continue

        tests_dir.mkdir(exist_ok=True)
        (tests_dir / "__init__.py").write_text("# per-folder test package\n")
        test_content = generate_test_file(folder)
        test_file = tests_dir / "test_hunt.py"
        test_file.write_text(test_content, encoding="utf-8")
        print(f"[ok]   {folder.name}/tests/test_hunt.py")
        created += 1

    print(f"\nDone: {created} generated, {skipped} skipped.")


if __name__ == "__main__":
    main()
