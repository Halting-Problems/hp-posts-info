"""
conftest.py — shared fixtures and folder discovery for hp-posts-info test suite.

Each subfolder of the workspace root is treated as an independent post/event folder.
Folders starting with '.' or that are known non-post directories are excluded.
"""

import json
import ast
from pathlib import Path
import pytest
import yaml

# ---------------------------------------------------------------------------
# Root of the repository (parent of tests/)
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent

# Folders that are NOT post folders
_EXCLUDED = {
    ".git", ".venv", ".pytest_cache", "tests", "__pycache__",
    # Protected scanner package: never collect, copy, index, or execute it.
    "shai-hulululud-ai-scanner-disruption-package",
}

# Required keys at the top level of iocs.json
IOCS_REQUIRED_TOP_LEVEL_KEYS = [
    "schema_version",
    "event_id",
    "event_name",
    "attack_types",
    "sources",
    "affected_assets",
    "timeline",
    "artifact_analysis",
    "iocs",
    "detection",
    "open_questions",
    "defender_takeaways",
    "remediation_gates",
]

# Required keys inside iocs.json["iocs"]
IOCS_REQUIRED_IOC_KEYS = [
    "package_versions",
    "files",
    "hashes",
    "domains",
    "urls",
    "ips",
    "process_patterns",
    "network_patterns",
]

# Required keys inside iocs.json["detection"]
IOCS_REQUIRED_DETECTION_KEYS = [
    "lockfile_hunts",
    "filesystem_hunts",
    "process_hunts",
    "network_hunts",
    "ci_cd_hunts",
    "registry_hunts",
]

# Required keys inside iocs.json["timeline"]
IOCS_REQUIRED_TIMELINE_KEYS = [
    "first_seen",
    "malicious_publish_time",
    "discovery_time",
    "removal_time",
    "disclosure_time",
    "patch_or_fix_time",
]

# Required manifest keys inside each hunt entry
MANIFEST_REQUIRED_HUNT_KEYS = [
    "id",
    "title",
    "question",
    "telemetry",
    "positive_signal",
    "script_path",
]


def _is_post_folder(path: Path) -> bool:
    """Return True if `path` looks like a post/event folder."""
    return (
        path.is_dir()
        and path.name not in _EXCLUDED
        and not path.name.startswith("hp-")
        and not path.name.startswith(".")
    )


def collect_post_folders() -> list[Path]:
    """Return sorted list of all post folders under REPO_ROOT."""
    return sorted(p for p in REPO_ROOT.iterdir() if _is_post_folder(p))


POST_FOLDERS = collect_post_folders()
POST_FOLDER_IDS = [p.name for p in POST_FOLDERS]


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def iocs_data(post_folder):
    """Load and return the parsed iocs.json for a given post folder."""
    iocs_path = post_folder / "iocs.json"
    assert iocs_path.exists(), f"iocs.json not found in {post_folder.name}"
    with iocs_path.open() as f:
        return json.load(f)


@pytest.fixture
def manifest_data(post_folder):
    """Load and return the parsed manifest.yaml for a given post folder."""
    manifest_path = post_folder / "manifest.yaml"
    assert manifest_path.exists(), f"manifest.yaml not found in {post_folder.name}"
    with manifest_path.open() as f:
        return yaml.safe_load(f)


@pytest.fixture
def script_path(post_folder):
    """Return the Path to the hunt script declared in manifest.yaml."""
    manifest_path = post_folder / "manifest.yaml"
    with manifest_path.open() as f:
        manifest = yaml.safe_load(f)
    declared = manifest["hunts"][0]["script_path"]
    return post_folder / declared
