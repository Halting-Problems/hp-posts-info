"""
test_manifest.py — validates manifest.yaml for every post folder independently.

Each post folder is parametrized as a separate test case. The tests verify:
  - manifest.yaml exists and is valid YAML
  - required top-level structure is present
  - every hunt entry has all required fields
  - the script_path declared in the manifest actually exists on disk
  - the hunt id matches the expected pattern derived from the folder name
"""

import pytest
import yaml
from pathlib import Path
from .conftest import POST_FOLDERS, POST_FOLDER_IDS, MANIFEST_REQUIRED_HUNT_KEYS


@pytest.mark.parametrize("post_folder", POST_FOLDERS, ids=POST_FOLDER_IDS)
class TestManifest:
    """One class → one parameterized folder → fully independent tests."""

    def test_manifest_exists(self, post_folder):
        """manifest.yaml must be present in the folder."""
        assert (post_folder / "manifest.yaml").exists(), (
            f"manifest.yaml missing from {post_folder.name}"
        )

    def test_manifest_is_valid_yaml(self, post_folder):
        """manifest.yaml must parse without errors."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        assert data is not None, "manifest.yaml parsed to None (empty file?)"

    def test_manifest_has_hunts_key(self, post_folder):
        """manifest.yaml must have a top-level 'hunts' list."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        assert "hunts" in data, "Missing top-level 'hunts' key"
        assert isinstance(data["hunts"], list), "'hunts' must be a list"
        if not data["hunts"]:
            assert data.get("hunt_status") == "not_applicable"
            assert isinstance(data.get("hunt_reason"), str) and data["hunt_reason"].strip()

    def test_manifest_hunt_required_fields(self, post_folder):
        """Every hunt entry must have all required fields."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        for i, hunt in enumerate(data.get("hunts", [])):
            for key in MANIFEST_REQUIRED_HUNT_KEYS:
                assert key in hunt, (
                    f"Hunt[{i}] in {post_folder.name}/manifest.yaml missing required key '{key}'"
                )

    def test_manifest_hunt_id_nonempty(self, post_folder):
        """Every hunt id must be a non-empty string."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        for i, hunt in enumerate(data.get("hunts", [])):
            hunt_id = hunt.get("id", "")
            assert isinstance(hunt_id, str) and hunt_id.strip(), (
                f"Hunt[{i}] id is empty or not a string in {post_folder.name}"
            )

    def test_manifest_hunt_id_contains_folder_name(self, post_folder):
        """Hunt id should be namespaced with the folder name for traceability."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        folder_name = post_folder.name
        for i, hunt in enumerate(data.get("hunts", [])):
            hunt_id = hunt.get("id", "")
            assert folder_name in hunt_id, (
                f"Hunt[{i}] id '{hunt_id}' does not contain folder name '{folder_name}'"
            )

    def test_manifest_script_path_exists(self, post_folder):
        """The script_path declared in each hunt must exist on disk."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        for i, hunt in enumerate(data.get("hunts", [])):
            script_rel = hunt.get("script_path", "")
            assert script_rel, f"Hunt[{i}] has empty script_path in {post_folder.name}"
            script_abs = post_folder / script_rel
            assert script_abs.exists(), (
                f"Hunt[{i}] script_path '{script_rel}' does not exist "
                f"(resolved: {script_abs})"
            )

    def test_manifest_telemetry_has_family(self, post_folder):
        """Each hunt's telemetry block must have a 'family' field."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        for i, hunt in enumerate(data.get("hunts", [])):
            telemetry = hunt.get("telemetry", {})
            assert "family" in telemetry, (
                f"Hunt[{i}] telemetry block missing 'family' in {post_folder.name}"
            )
            assert telemetry["family"], (
                f"Hunt[{i}] telemetry.family is empty in {post_folder.name}"
            )

    def test_manifest_question_nonempty(self, post_folder):
        """Each hunt question must be a non-empty string."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        for i, hunt in enumerate(data.get("hunts", [])):
            question = hunt.get("question", "")
            assert question and question.strip(), (
                f"Hunt[{i}] question is empty in {post_folder.name}"
            )

    def test_manifest_positive_signal_nonempty(self, post_folder):
        """Each hunt positive_signal must be a non-empty string."""
        path = post_folder / "manifest.yaml"
        with path.open() as f:
            data = yaml.safe_load(f)
        for i, hunt in enumerate(data.get("hunts", [])):
            sig = hunt.get("positive_signal", "")
            assert sig and sig.strip(), (
                f"Hunt[{i}] positive_signal is empty in {post_folder.name}"
            )
