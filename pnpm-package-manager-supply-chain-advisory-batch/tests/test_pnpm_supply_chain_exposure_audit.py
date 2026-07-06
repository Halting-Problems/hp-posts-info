from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pnpm_supply_chain_exposure_audit.py"


def run_scan(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(root)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def parse_stdout(proc: subprocess.CompletedProcess[str]) -> dict:
    assert proc.stderr == ""
    return json.loads(proc.stdout)


def test_clean_repository_returns_zero(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"packageManager":"pnpm@11.5.3"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text('registry=https://registry.npmjs.org/\n', encoding="utf-8")

    proc = run_scan(tmp_path)

    data = parse_stdout(proc)
    assert proc.returncode == 0
    assert data["finding_count"] == 0
    assert data["package_name_iocs"] == ["pnpm"]
    assert data["package_version_iocs"] == []
    assert "vulnerable_version_ranges" not in data
    assert data["advisory_ids"] == [
        "GHSA-hg3w-7f8c-63hp",
        "GHSA-54hh-g5mx-jqcp",
        "GHSA-q6j5-fjx5-2mc3",
        "GHSA-p4xf-rf54-rj3x",
        "GHSA-hwx4-2j3j-g496",
        "GHSA-cjhr-43r9-cfmw",
        "GHSA-rxhj-4m44-96r4",
        "GHSA-3qhv-2rgh-x77r",
    ]


def test_vulnerable_pnpm_version_returns_alert(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"packageManager":"pnpm@10.33.2"}', encoding="utf-8")

    proc = run_scan(tmp_path)

    data = parse_stdout(proc)
    assert proc.returncode == 1
    assert data["finding_count"] == 1
    assert data["files_with_findings"][0]["findings"][0]["type"] == "vulnerable_pnpm_version"
    assert data["files_with_findings"][0]["findings"][0]["indicator"] == "pnpm@10.33.2"
    assert data["package_version_iocs"] == ["pnpm@10.33.2"]
    assert "vulnerable_version_ranges" not in data
    assert all(value.startswith("pnpm@") for value in data["package_version_iocs"])
    assert all(" " not in value and "<" not in value and ">" not in value for value in data["package_version_iocs"])


def test_repository_npmrc_registry_auth_review_returns_alert(tmp_path: Path) -> None:
    (tmp_path / ".npmrc").write_text(
        "registry=https://packages.example.invalid/npm/\n//packages.example.invalid/npm/:_authToken=${NPM_TOKEN}\n",
        encoding="utf-8",
    )

    proc = run_scan(tmp_path)

    data = parse_stdout(proc)
    assert proc.returncode == 1
    finding_types = [finding["type"] for item in data["files_with_findings"] for finding in item["findings"]]
    assert "registry_auth_review" in finding_types


def test_patch_traversal_returns_alert(tmp_path: Path) -> None:
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "patchedDependencies:\n  left-pad@1.3.0: patches/left-pad.patch\n",
        encoding="utf-8",
    )
    patches = tmp_path / "patches"
    patches.mkdir()
    (patches / "left-pad.patch").write_text(
        "diff --git a/../../.github/workflows/release.yml b/../../.github/workflows/release.yml\n",
        encoding="utf-8",
    )

    proc = run_scan(tmp_path)

    data = parse_stdout(proc)
    assert proc.returncode == 1
    all_types = {finding["type"] for item in data["files_with_findings"] for finding in item["findings"]}
    assert "patch_traversal_review" in all_types


def test_missing_root_returns_two(tmp_path: Path) -> None:
    proc = run_scan(tmp_path / "missing")
    assert proc.returncode == 2
    assert "evidence root not found" in proc.stdout
