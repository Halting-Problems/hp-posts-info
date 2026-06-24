#!/usr/bin/env python3
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

FOLDER = Path(__file__).resolve().parent.parent
SCRIPT = FOLDER / "scripts" / "local_repository_and_exported_telemetry_scope.py"
IOCS_JSON = FOLDER / "iocs.json"


def load_iocs() -> dict:
    return json.loads(IOCS_JSON.read_text(encoding="utf-8"))


def extract_list_constant(tree: ast.Module, variable_name: str):
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == variable_name:
                    if isinstance(node.value, ast.List):
                        values = []
                        for item in node.value.elts:
                            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                                values.append(item.value)
                        return values
    return None


def run_scan(scan_dir: Path, out_dir: Path):
    env = os.environ.copy()
    env["OUT"] = str(out_dir)
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(scan_dir)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def test_script_parses():
    ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))


def test_packages_and_hashes_match_iocs():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    iocs = load_iocs()
    packages = extract_list_constant(tree, "PACKAGES")
    hashes = extract_list_constant(tree, "HASHES")
    assert packages is not None
    assert hashes is not None
    assert sorted(packages) == sorted(iocs["affected_assets"]["packages"])
    assert sorted(hashes) == sorted(iocs["iocs"]["hashes"])


def test_clean_directory_has_no_matches(tmp_path: Path):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    run_scan(scan_dir, out_dir)

    assert (out_dir / "indicators.txt").exists()
    assert not (out_dir / "repository-indicator-matches.txt").exists()


def test_detects_compromised_action_reference(tmp_path: Path):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    workflow = scan_dir / "release.yml"
    workflow.write_text(
        "uses: codfish/semantic-release-action@v5\n# commit 5792aba0e2180b9b80b77644370a6889d5817456\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    run_scan(scan_dir, out_dir)

    matches = (out_dir / "repository-indicator-matches.txt").read_text(encoding="utf-8")
    assert "codfish/semantic-release-action@v5" in matches
    assert "5792aba0e2180b9b80b77644370a6889d5817456" in matches
