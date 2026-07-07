"""
test_folder_structure.py — validates the physical folder structure for every post folder.

These tests are independent of file contents and simply verify that the
expected files and directories exist in the right places.
"""

import pytest
from pathlib import Path
from .conftest import POST_FOLDERS, POST_FOLDER_IDS


@pytest.mark.parametrize("post_folder", POST_FOLDERS, ids=POST_FOLDER_IDS)
class TestFolderStructure:
    """One class → one parameterized folder → fully independent tests."""

    def test_folder_exists_and_is_directory(self, post_folder):
        """The post folder itself must exist and be a directory."""
        assert post_folder.exists(), f"Post folder does not exist: {post_folder}"
        assert post_folder.is_dir(), f"Post folder is not a directory: {post_folder}"

    def test_iocs_json_present(self, post_folder):
        """iocs.json must be present at the top level of the post folder."""
        assert (post_folder / "iocs.json").is_file(), (
            f"iocs.json missing from {post_folder.name}"
        )

    def test_manifest_yaml_present(self, post_folder):
        """manifest.yaml must be present at the top level of the post folder."""
        assert (post_folder / "manifest.yaml").is_file(), (
            f"manifest.yaml missing from {post_folder.name}"
        )

    def test_scripts_directory_present(self, post_folder):
        """A scripts/ sub-directory must exist inside the post folder."""
        assert (post_folder / "scripts").is_dir(), (
            f"scripts/ directory missing from {post_folder.name}"
        )

    def test_scripts_directory_not_empty(self, post_folder):
        """The scripts/ directory must contain at least one Python file."""
        scripts_dir = post_folder / "scripts"
        py_files = list(scripts_dir.glob("*.py"))
        assert len(py_files) >= 1, (
            f"scripts/ in {post_folder.name} has no .py files"
        )

    def test_analysis_markdown_present(self, post_folder):
        """Publish-ready folders must include long-form narrative analysis."""
        assert (post_folder / "analysis.md").is_file() or (post_folder / "analysis.mdx").is_file(), (
            f"analysis.md or analysis.mdx missing from {post_folder.name}"
        )

    def test_no_unexpected_top_level_files(self, post_folder):
        """
        Top-level files should only be iocs.json, manifest.yaml, and analysis.md/mdx.
        Extra files are flagged as unexpected to keep folders tidy.
        """
        allowed_files = {"iocs.json", "manifest.yaml", "analysis.md", "analysis.mdx"}
        actual_files = {f.name for f in post_folder.iterdir() if f.is_file()}
        unexpected = actual_files - allowed_files
        assert not unexpected, (
            f"Unexpected top-level files in {post_folder.name}: {sorted(unexpected)}"
        )

    def test_no_pycache_at_top_level(self, post_folder):
        """__pycache__ should not appear at the top level of a post folder."""
        assert not (post_folder / "__pycache__").exists(), (
            f"__pycache__ found at top level of {post_folder.name} — add to .gitignore"
        )

    def test_folder_name_is_kebab_case(self, post_folder):
        """Folder names should use lowercase kebab-case for consistency."""
        name = post_folder.name
        import re
        assert re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", name), (
            f"Folder name '{name}' is not kebab-case (lowercase letters, digits, hyphens only)"
        )
