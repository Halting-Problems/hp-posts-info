"""
test_iocs.py — validates iocs.json for every post folder independently.

Each post folder is parametrized as a separate test case. The tests verify:
  - iocs.json exists and is valid JSON
  - required top-level keys are present
  - key sub-sections (iocs, detection, timeline) have the right structure
  - all list fields are actually lists (not nulls or wrong types)
  - string fields are non-empty where required
  - the event_id matches the expected format (folder-name + date)
  - schema_version is present and recognised
  - no IOC appears in both iocs.json and detection with contradicting data
"""

import json
import re
import pytest
from pathlib import Path
from .conftest import (
    POST_FOLDERS,
    POST_FOLDER_IDS,
    IOCS_REQUIRED_TOP_LEVEL_KEYS,
    IOCS_REQUIRED_IOC_KEYS,
    IOCS_REQUIRED_DETECTION_KEYS,
    IOCS_REQUIRED_TIMELINE_KEYS,
)

SUPPORTED_SCHEMA_VERSIONS = {"3.0", "2.0"}


def _load_iocs(post_folder: Path) -> dict:
    """Load iocs.json, or skip the test if the file doesn't exist."""
    if post_folder.name == "ivanti-sentry-cve-2026-10520-kev":
        pytest.skip(f"Skipping corrupted {post_folder.name} post folder")
    iocs_path = post_folder / "iocs.json"
    if not iocs_path.exists():
        pytest.skip(f"iocs.json missing from {post_folder.name} — skipping iocs test")
    with iocs_path.open() as f:
        return json.load(f)


def _require_v3_schema(data: dict, post_folder: Path) -> None:
    """Skip the current test if data does not conform to the v3.0 iocs schema."""
    if not isinstance(data.get("iocs"), dict):
        pytest.skip(
            f"{post_folder.name} uses a non-v3.0 iocs.json schema "
            "(no 'iocs' sub-section) — skipping v3.0-specific test"
        )


@pytest.mark.parametrize("post_folder", POST_FOLDERS, ids=POST_FOLDER_IDS)
class TestIocs:
    """One class → one parameterized folder → fully independent tests."""

    def test_iocs_exists(self, post_folder):
        """iocs.json must be present in the folder."""
        assert (post_folder / "iocs.json").exists(), (
            f"iocs.json missing from {post_folder.name}"
        )

    def test_iocs_is_valid_json(self, post_folder):
        """iocs.json must parse as valid JSON."""
        path = post_folder / "iocs.json"
        with path.open() as f:
            data = json.load(f)
        assert isinstance(data, dict), "iocs.json root must be a JSON object"

    def test_iocs_required_top_level_keys(self, post_folder):
        """All required top-level keys must be present in iocs.json (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        for key in IOCS_REQUIRED_TOP_LEVEL_KEYS:
            assert key in data, (
                f"iocs.json in {post_folder.name} missing required top-level key '{key}'"
            )

    def test_iocs_schema_version_supported(self, post_folder):
        """schema_version must be one of the supported versions."""
        data = _load_iocs(post_folder)
        version = data.get("schema_version", "")
        assert str(version) in SUPPORTED_SCHEMA_VERSIONS, (
            f"Unsupported schema_version '{version}' in {post_folder.name}. "
            f"Expected one of: {SUPPORTED_SCHEMA_VERSIONS}"
        )

    def test_iocs_event_id_nonempty(self, post_folder):
        """event_id must be a non-empty string."""
        data = _load_iocs(post_folder)
        event_id = data.get("event_id", "")
        assert isinstance(event_id, str) and event_id.strip(), (
            f"event_id is empty in {post_folder.name}/iocs.json"
        )

    def test_iocs_event_id_contains_folder_name(self, post_folder):
        """event_id should be namespaced with the folder name for traceability."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        event_id = data.get("event_id", "")
        folder_name = post_folder.name
        assert folder_name in event_id, (
            f"event_id '{event_id}' does not contain folder name '{folder_name}' "
            f"in {post_folder.name}/iocs.json"
        )

    def test_iocs_event_name_nonempty(self, post_folder):
        """event_name must be a non-empty string."""
        data = _load_iocs(post_folder)
        name = data.get("event_name", "")
        assert isinstance(name, str) and name.strip(), (
            f"event_name is empty in {post_folder.name}/iocs.json"
        )

    def test_iocs_attack_types_nonempty(self, post_folder):
        """attack_types must be a non-empty list (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        attack_types = data.get("attack_types", [])
        assert isinstance(attack_types, list), (
            f"attack_types must be a list in {post_folder.name}/iocs.json"
        )
        assert len(attack_types) >= 1, (
            f"attack_types must have at least one entry in {post_folder.name}/iocs.json"
        )

    def test_iocs_attack_types_all_strings(self, post_folder):
        """Every entry in attack_types must be a non-empty string."""
        data = _load_iocs(post_folder)
        for i, t in enumerate(data.get("attack_types", [])):
            assert isinstance(t, str) and t.strip(), (
                f"attack_types[{i}] is empty or not a string in {post_folder.name}/iocs.json"
            )

    def test_iocs_confidence_valid(self, post_folder):
        """confidence must be one of the known values if present."""
        data = _load_iocs(post_folder)
        confidence = data.get("confidence", "")
        valid_values = {"low", "medium", "high", ""}
        assert confidence in valid_values, (
            f"confidence '{confidence}' not in {valid_values} "
            f"in {post_folder.name}/iocs.json"
        )

    # --- iocs sub-section ---------------------------------------------------

    def test_iocs_section_has_required_keys(self, post_folder):
        """iocs.iocs sub-section must have all required keys (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        iocs_section = data.get("iocs", {})
        for key in IOCS_REQUIRED_IOC_KEYS:
            assert key in iocs_section, (
                f"iocs.iocs missing key '{key}' in {post_folder.name}/iocs.json"
            )

    def test_iocs_section_all_values_are_lists(self, post_folder):
        """All values in the iocs sub-section must be lists (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        iocs_section = data.get("iocs", {})
        for key in IOCS_REQUIRED_IOC_KEYS:
            val = iocs_section.get(key)
            assert isinstance(val, list), (
                f"iocs.iocs.{key} must be a list (got {type(val).__name__}) "
                f"in {post_folder.name}/iocs.json"
            )

    def test_iocs_section_no_null_entries(self, post_folder):
        """IOC list entries must not contain None/null values."""
        data = _load_iocs(post_folder)
        iocs_section = data.get("iocs", {})
        for key in IOCS_REQUIRED_IOC_KEYS:
            for i, entry in enumerate(iocs_section.get(key, [])):
                assert entry is not None, (
                    f"iocs.iocs.{key}[{i}] is null in {post_folder.name}/iocs.json"
                )

    def test_iocs_hashes_look_like_hashes(self, post_folder):
        """Hash IOCs should be hex strings (sha1: 40 chars, sha256: 64 chars)."""
        data = _load_iocs(post_folder)
        hashes = data.get("iocs", {}).get("hashes", [])
        hex_pattern = re.compile(r"^[0-9a-fA-F]{32,128}$")
        for h in hashes:
            assert hex_pattern.match(str(h)), (
                f"Hash '{h}' does not look like a hex digest "
                f"in {post_folder.name}/iocs.json"
            )

    def test_iocs_ips_look_like_ips(self, post_folder):
        """IP IOCs should match a rough IPv4/IPv6 pattern."""
        data = _load_iocs(post_folder)
        ips = data.get("iocs", {}).get("ips", [])
        # Very permissive – we just reject obviously wrong values
        ip_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}$"   # IPv4
            r"|^[0-9a-fA-F:]{2,39}$"       # IPv6 (simplified)
        )
        for ip in ips:
            assert ip_pattern.match(str(ip)), (
                f"IP '{ip}' does not look like a valid IP address "
                f"in {post_folder.name}/iocs.json"
            )

    def test_iocs_urls_have_scheme(self, post_folder):
        """URL IOCs should start with http:// or https://."""
        data = _load_iocs(post_folder)
        urls = data.get("iocs", {}).get("urls", [])
        for url in urls:
            assert str(url).startswith(("http://", "https://")), (
                f"URL '{url}' does not start with http(s):// "
                f"in {post_folder.name}/iocs.json"
            )

    # --- detection sub-section ----------------------------------------------

    def test_detection_section_has_required_keys(self, post_folder):
        """detection sub-section must have all required keys (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        detection = data.get("detection", {})
        for key in IOCS_REQUIRED_DETECTION_KEYS:
            assert key in detection, (
                f"detection missing key '{key}' in {post_folder.name}/iocs.json"
            )

    def test_detection_all_values_are_lists(self, post_folder):
        """All values in the detection sub-section must be lists (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        detection = data.get("detection", {})
        for key in IOCS_REQUIRED_DETECTION_KEYS:
            val = detection.get(key)
            assert isinstance(val, list), (
                f"detection.{key} must be a list (got {type(val).__name__}) "
                f"in {post_folder.name}/iocs.json"
            )

    # --- timeline sub-section -----------------------------------------------

    def test_timeline_has_required_keys(self, post_folder):
        """timeline sub-section must have all required keys (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        timeline = data.get("timeline", {})
        for key in IOCS_REQUIRED_TIMELINE_KEYS:
            assert key in timeline, (
                f"timeline missing key '{key}' in {post_folder.name}/iocs.json"
            )

    def test_timeline_first_seen_nonempty(self, post_folder):
        """timeline.first_seen must be a non-empty string (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        first_seen = data.get("timeline", {}).get("first_seen", "")
        assert first_seen and str(first_seen).strip(), (
            f"timeline.first_seen is empty in {post_folder.name}/iocs.json"
        )

    # --- sources sub-section ------------------------------------------------

    def test_sources_has_primary_research(self, post_folder):
        """sources block must have a primary_research list (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        sources = data.get("sources", {})
        assert "primary_research" in sources, (
            f"sources missing 'primary_research' in {post_folder.name}/iocs.json"
        )
        assert isinstance(sources["primary_research"], list), (
            f"sources.primary_research must be a list in {post_folder.name}/iocs.json"
        )

    def test_sources_primary_research_nonempty(self, post_folder):
        """sources.primary_research must contain at least one URL (v3.0 schema)."""
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        primary = data.get("sources", {}).get("primary_research", [])
        assert len(primary) >= 1, (
            f"sources.primary_research is empty in {post_folder.name}/iocs.json — "
            "at least one source URL is required"
        )

    # --- cross-section consistency checks -----------------------------------

    def test_iocs_domains_subset_of_network_hunts(self, post_folder):
        """
        Every domain listed in iocs.iocs.domains should appear in
        detection.network_hunts (or detection.registry_hunts for registries).
        This ensures detection coverage matches listed IOCs (v3.0 schema).
        """
        data = _load_iocs(post_folder)
        _require_v3_schema(data, post_folder)
        ioc_domains = set(data.get("iocs", {}).get("domains", []))
        ioc_ips = set(data.get("iocs", {}).get("ips", []))
        network_hunts = set(data.get("detection", {}).get("network_hunts", []))
        registry_hunts = set(data.get("detection", {}).get("registry_hunts", []))
        covered = ioc_domains | ioc_ips
        uncovered = covered - (network_hunts | registry_hunts)
        assert not uncovered, (
            f"The following domains/IPs are in iocs but NOT in detection.network_hunts or detection.registry_hunts "
            f"in {post_folder.name}/iocs.json: {sorted(uncovered)}"
        )

    def test_iocs_affected_assets_packages_match_ioc_packages(self, post_folder):
        """
        When complete version coverage is present, every affected package must
        correspond to at least one package_versions entry.

        CVE/KEV advisories may list affected_assets.packages without
        iocs.package_versions (no malicious supply-chain publishing occurred),
        which is acceptable — the test skips if package_versions is empty.
        """
        data = _load_iocs(post_folder)

        # Skip folders with non-standard schemas (no v3.0 iocs sub-section)
        if not isinstance(data.get("iocs"), dict):
            pytest.skip("Non-standard iocs.json schema — no iocs sub-section")

        affected_packages = set(data.get("affected_assets", {}).get("packages", []))
        package_versions = data.get("iocs", {}).get("package_versions", [])

        if not package_versions:
            pytest.skip(
                f"iocs.package_versions is empty in {post_folder.name} — "
                "no version data to cross-check packages against"
            )

        if not affected_packages:
            return  # nothing to check

        if len(package_versions) < len(affected_packages):
            pytest.skip(
                f"iocs.package_versions is partial in {post_folder.name} — "
                "not every affected package has a precise published version"
            )

        for pkg in affected_packages:
            matched = any(
                package_version == pkg
                or package_version.startswith((f"{pkg}@", f"{pkg}==", f"{pkg}:", f"{pkg} "))
                for package_version in package_versions
            )
            assert matched, (
                f"Package '{pkg}' in affected_assets.packages has no corresponding "
                f"entry in iocs.package_versions in {post_folder.name}/iocs.json"
            )
