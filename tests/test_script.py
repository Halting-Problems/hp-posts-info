"""
test_script.py — validates the hunt script in every post folder independently.

Each post folder is parametrized as a separate test case. The tests verify:
  - The script file declared in manifest.yaml exists and is executable Python
  - The script has no syntax errors (via AST parse)
  - The script defines the required configuration constants (DOMAINS, HASHES, etc.)
  - The IOC values in the constants match those declared in iocs.json
  - The script does not contain obviously dangerous unchecked network calls
  - The OUT variable is correctly named for the folder
"""

import ast
import json
import re
from pathlib import Path
import pytest
import yaml

from .conftest import POST_FOLDERS, POST_FOLDER_IDS
from .ioc_quality import find_script_coverage_errors


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def _load_iocs(post_folder: Path) -> dict:
    with (post_folder / "iocs.json").open() as f:
        return json.load(f)


def _load_manifest(post_folder: Path) -> dict:
    with (post_folder / "manifest.yaml").open() as f:
        return yaml.safe_load(f)


def _get_script_paths(post_folder: Path) -> list[Path]:
    manifest = _load_manifest(post_folder)
    return [post_folder / hunt["script_path"] for hunt in manifest.get("hunts", [])]


def _parse_script(script_path: Path) -> ast.Module:
    source = script_path.read_text(encoding="utf-8")
    return ast.parse(source, filename=str(script_path))


def _extract_top_level_list_constant(tree: ast.Module, var_name: str) -> list[str] | None:
    """
    Return the list of string values assigned to `var_name` at module top-level,
    or None if the assignment is not found.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    val = node.value
                    if isinstance(val, ast.List):
                        result = []
                        for elt in val.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                result.append(elt.value)
                        return result
    return None


def _extract_string_constant(tree: ast.Module, var_name: str) -> str | None:
    """Return the string value assigned to `var_name` at module top-level, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    val = node.value
                    if isinstance(val, ast.Constant) and isinstance(val.value, str):
                        return val.value
    return None


def _is_scope_scanner_script(script_path: Path) -> bool:
    """Return True if the script is the standard IOC scope scanner."""
    try:
        source = script_path.read_text(encoding="utf-8")
        return "indicators = set()" in source and "os.walk" in source
    except Exception:
        return False


def _has_v3_iocs_schema(post_folder: Path) -> bool:
    """Return True if iocs.json follows the v3.0 schema with an 'iocs' sub-section."""
    try:
        with (post_folder / "iocs.json").open() as f:
            data = json.load(f)
        return isinstance(data.get("iocs"), dict)
    except Exception:
        return False


# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------

@pytest.mark.parametrize("post_folder", POST_FOLDERS, ids=POST_FOLDER_IDS)
class TestScript:
    """One class → one parameterized folder → fully independent tests."""

    def test_script_exists(self, post_folder):
        """The script_path declared in manifest.yaml must exist on disk."""
        scripts = _get_script_paths(post_folder)
        for script in scripts:
            assert script.exists(), (
                f"Script {script} declared in manifest does not exist"
            )

    def test_script_has_no_syntax_errors(self, post_folder):
        """The script must parse as valid Python (no SyntaxError)."""
        scripts = _get_script_paths(post_folder)
        for script in scripts:
            source = script.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(script))
            except SyntaxError as exc:
                pytest.fail(
                    f"SyntaxError in {post_folder.name}/{script.name}: {exc}"
                )

    def test_script_has_shebang(self, post_folder):
        """Script should have a Python shebang line for standalone execution."""
        scripts = _get_script_paths(post_folder)
        for script in scripts:
            first_line = script.read_text(encoding="utf-8").splitlines()[0]
            assert first_line.startswith("#!") and "python" in first_line.lower(), (
                f"Script {script.name} in {post_folder.name} missing python shebang on line 1: '{first_line}'"
            )

    def test_script_defines_out_variable(self, post_folder):
        """Scope-scanner scripts must define an OUT variable with a folder-namespaced default."""
        scripts = _get_script_paths(post_folder)
        scope_scanners = [s for s in scripts if _is_scope_scanner_script(s)]
        if not scope_scanners:
            pytest.skip(f"No scope-scanner scripts found in {post_folder.name}")
        for script in scope_scanners:
            source = script.read_text(encoding="utf-8")
            folder_name = post_folder.name
            expected_default = f"hp-{folder_name}-scope"
            assert expected_default in source, (
                f"Script {script.name} in {post_folder.name} does not contain expected OUT default "
                f"'{expected_default}'"
            )

    def test_script_defines_indicators_set(self, post_folder):
        """Scope-scanner scripts must create an 'indicators' set for IOC collection."""
        scripts = _get_script_paths(post_folder)
        scope_scanners = [s for s in scripts if _is_scope_scanner_script(s)]
        if not scope_scanners:
            pytest.skip(f"No scope-scanner scripts found in {post_folder.name}")
        for script in scope_scanners:
            source = script.read_text(encoding="utf-8")
            assert "indicators = set()" in source, (
                f"Script {script.name} in {post_folder.name} missing 'indicators = set()' pattern"
            )

    def test_script_walks_directory(self, post_folder):
        """Scope-scanner scripts must include an os.walk call to scan a directory."""
        scripts = _get_script_paths(post_folder)
        scope_scanners = [s for s in scripts if _is_scope_scanner_script(s)]
        if not scope_scanners:
            pytest.skip(f"No scope-scanner scripts found in {post_folder.name}")
        for script in scope_scanners:
            source = script.read_text(encoding="utf-8")
            assert "os.walk" in source, (
                f"Script {script.name} in {post_folder.name} missing os.walk call"
            )

    def test_script_domains_match_iocs(self, post_folder):
        """
        If iocs.json has domain IOCs, the scope-scanner script's DOMAINS constant
        must contain exactly those same values.
        """
        if not _has_v3_iocs_schema(post_folder):
            pytest.skip(f"{post_folder.name} has non-v3.0 iocs.json schema")
        data = _load_iocs(post_folder)
        expected_domains = sorted(data.get("iocs", {}).get("domains", []))
        if not expected_domains:
            pytest.skip("No domains in iocs.json — nothing to compare")

        scripts = _get_script_paths(post_folder)
        scope_scanners = [s for s in scripts if _is_scope_scanner_script(s)]
        if not scope_scanners:
            pytest.skip(f"No scope-scanner scripts found in {post_folder.name}")
        for script in scope_scanners:
            tree = _parse_script(script)
            script_domains = _extract_top_level_list_constant(tree, "DOMAINS")

            assert script_domains is not None, (
                f"Script {script.name} in {post_folder.name} missing DOMAINS constant "
                f"but iocs.json has domain IOCs: {expected_domains}"
            )
            assert sorted(script_domains) == expected_domains, (
                f"DOMAINS in script {script.name} does not match iocs.json for {post_folder.name}.\n"
                f"  script DOMAINS = {sorted(script_domains)}\n"
                f"  iocs.json domains = {expected_domains}"
            )

    def test_script_hashes_match_iocs(self, post_folder):
        """
        If iocs.json has hash IOCs, the scope-scanner script's HASHES constant
        must contain exactly those same values.
        """
        if not _has_v3_iocs_schema(post_folder):
            pytest.skip(f"{post_folder.name} has non-v3.0 iocs.json schema")
        data = _load_iocs(post_folder)
        expected_hashes = sorted(data.get("iocs", {}).get("hashes", []))
        if not expected_hashes:
            pytest.skip("No hashes in iocs.json — nothing to compare")

        scripts = _get_script_paths(post_folder)
        scope_scanners = [s for s in scripts if _is_scope_scanner_script(s)]
        if not scope_scanners:
            pytest.skip(f"No scope-scanner scripts found in {post_folder.name}")
        for script in scope_scanners:
            tree = _parse_script(script)
            script_hashes = _extract_top_level_list_constant(tree, "HASHES")

            assert script_hashes is not None, (
                f"Script {script.name} in {post_folder.name} missing HASHES constant "
                f"but iocs.json has hash IOCs: {expected_hashes}"
            )
            assert sorted(script_hashes) == expected_hashes, (
                f"HASHES in script {script.name} does not match iocs.json for {post_folder.name}.\n"
                f"  script HASHES = {sorted(script_hashes)}\n"
                f"  iocs.json hashes = {expected_hashes}"
            )

    def test_script_packages_match_iocs(self, post_folder):
        """
        If iocs.json has package IOCs, the scope-scanner script's PACKAGES constant
        must contain the same values (order-independent).
        """
        if not _has_v3_iocs_schema(post_folder):
            pytest.skip(f"{post_folder.name} has non-v3.0 iocs.json schema")
        data = _load_iocs(post_folder)
        expected_packages = sorted(data.get("affected_assets", {}).get("packages", []))
        if not expected_packages:
            pytest.skip("No packages in affected_assets — nothing to compare")

        scripts = _get_script_paths(post_folder)
        scope_scanners = [s for s in scripts if _is_scope_scanner_script(s)]
        if not scope_scanners:
            pytest.skip(f"No scope-scanner scripts found in {post_folder.name}")
        for script in scope_scanners:
            tree = _parse_script(script)
            script_packages = _extract_top_level_list_constant(tree, "PACKAGES")

            assert script_packages is not None, (
                f"Script {script.name} in {post_folder.name} missing PACKAGES constant "
                f"but iocs.json has package IOCs: {expected_packages}"
            )
            assert sorted(script_packages) == expected_packages, (
                f"PACKAGES in script {script.name} does not match iocs.json for {post_folder.name}.\n"
                f"  script PACKAGES = {sorted(script_packages)}\n"
                f"  iocs.json affected_assets.packages = {expected_packages}"
            )

    def test_script_ips_match_iocs(self, post_folder):
        """
        If iocs.json has IP IOCs, the scope-scanner script's IPS constant must
        contain exactly those same values.
        """
        if not _has_v3_iocs_schema(post_folder):
            pytest.skip(f"{post_folder.name} has non-v3.0 iocs.json schema")
        data = _load_iocs(post_folder)
        expected_ips = sorted(data.get("iocs", {}).get("ips", []))
        if not expected_ips:
            pytest.skip("No IPs in iocs.json — nothing to compare")

        scripts = _get_script_paths(post_folder)
        scope_scanners = [s for s in scripts if _is_scope_scanner_script(s)]
        if not scope_scanners:
            pytest.skip(f"No scope-scanner scripts found in {post_folder.name}")
        for script in scope_scanners:
            tree = _parse_script(script)
            script_ips = _extract_top_level_list_constant(tree, "IPS")

            assert script_ips is not None, (
                f"Script {script.name} in {post_folder.name} missing IPS constant "
                f"but iocs.json has IP IOCs: {expected_ips}"
            )
            assert sorted(script_ips) == expected_ips, (
                f"IPS in script {script.name} does not match iocs.json for {post_folder.name}.\n"
                f"  script IPS = {sorted(script_ips)}\n"
                f"  iocs.json ips = {expected_ips}"
            )

    def test_script_no_hardcoded_credentials(self, post_folder):
        """Script must not contain hardcoded API keys, tokens, or passwords."""
        scripts = _get_script_paths(post_folder)
        for script in scripts:
            source = script.read_text(encoding="utf-8").lower()
            suspicious_patterns = [
                r"api_key\s*=\s*['\"][^'\"]{8,}['\"]",
                r"password\s*=\s*['\"][^'\"]{4,}['\"]",
                r"secret\s*=\s*['\"][^'\"]{8,}['\"]",
                r"token\s*=\s*['\"][^'\"]{8,}['\"]",
            ]
            for pattern in suspicious_patterns:
                match = re.search(pattern, source)
                assert not match, (
                    f"Script {script.name} in {post_folder.name} may contain a hardcoded credential "
                    f"(matched pattern '{pattern}'): {match.group()!r}"
                )

    def test_script_does_not_exec_remote_code(self, post_folder):
        """Script must not fetch and exec/eval remote code."""
        scripts = _get_script_paths(post_folder)
        for script in scripts:
            source = script.read_text(encoding="utf-8")
            dangerous = re.search(
                r"\b(eval|exec)\s*\(\s*(urllib|requests|httpx|http\.client)",
                source,
            )
            assert not dangerous, (
                f"Script {script.name} in {post_folder.name} appears to fetch and exec remote code: "
                f"{dangerous.group()!r}"
            )

    def test_script_handles_file_read_errors(self, post_folder):
        """Script must use try/except around file reads to avoid crashing on bad files."""
        scripts = _get_script_paths(post_folder)
        for script in scripts:
            source = script.read_text(encoding="utf-8")
            assert "except" in source, (
                f"Script {script.name} in {post_folder.name} has no exception handling — "
                "file reads may crash on unreadable files"
            )

    def test_script_excludes_common_noise_dirs(self, post_folder):
        """Scope-scanner scripts should exclude common noisy directories from os.walk."""
        scripts = _get_script_paths(post_folder)
        scope_scanners = [s for s in scripts if _is_scope_scanner_script(s)]
        if not scope_scanners:
            pytest.skip(f"No scope-scanner scripts found in {post_folder.name}")
        for script in scope_scanners:
            source = script.read_text(encoding="utf-8")
            noise_dirs = {"node_modules", ".git"}
            for d in noise_dirs:
                assert d in source, (
                    f"Script {script.name} in {post_folder.name} does not exclude '{d}' from directory walk"
                )

    def test_ioc_values_are_represented_in_manifest_scripts(self, post_folder):
        """Durable IOC values must be represented in at least one script for this folder."""
        data = _load_iocs(post_folder)
        scripts = _get_script_paths(post_folder)
        errors = find_script_coverage_errors(data, scripts, post_folder.name)
        assert not errors, "\n".join(errors)


def test_script_coverage_rejects_unrepresented_iocs(tmp_path):
    """A listed IOC is not deployable if no script can detect it in files or logs."""
    script = tmp_path / "hunt.py"
    script.write_text("#!/usr/bin/env python3\nDOMAINS = ['evil.example']\n", encoding="utf-8")
    data = {
        "affected_assets": {"packages": ["missing-package"]},
        "iocs": {
            "package_versions": [],
            "files": [],
            "hashes": [],
            "domains": ["evil.example"],
            "urls": [],
            "ips": [],
            "process_patterns": [],
            "network_patterns": [],
        },
        "detection": {
            "lockfile_hunts": [],
            "filesystem_hunts": [],
            "process_hunts": [],
            "network_hunts": ["evil.example"],
            "ci_cd_hunts": [],
            "registry_hunts": [],
        },
    }

    errors = find_script_coverage_errors(data, [script], "coverage-test")

    assert any("missing-package" in error for error in errors)
