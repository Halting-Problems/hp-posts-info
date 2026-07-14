from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scan_lucide_proxy_exposure.py"
BROWSER_SCRIPT = ROOT / "scripts" / "collect_chromium_lucide_evidence.py"


def run_fixture(name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(ROOT / "fixtures" / name)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_clean_scope_returns_zero() -> None:
    result = run_fixture("clean")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "clean"
    assert payload["finding_count"] == 0


def test_dirty_scope_returns_alert_with_correlated_selectors() -> None:
    result = run_fixture("dirty")
    assert result.returncode == 1, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "alert"
    selectors = {(item["type"], item["value"]) for item in payload["findings"]}
    assert ("package_version", "charlie-kirk@3.0.1") in selectors
    assert ("domain", "lucideon.top") in selectors
    assert ("campaign_identifier", "G-0VL3ZSBXDH") in selectors
    assert ("ip", "92.38.177.17") in selectors
    assert ("sha256", "4b188d179e50e8208a6efec85e273e88d8fc390c836f299ba12915e0840408fd") in selectors


def test_missing_scope_returns_collection_failure() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(ROOT / "fixtures" / "does-not-exist")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "collection_failure"


def make_history(path: Path, rows: list[tuple[str, str, int]]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE urls (url TEXT, title TEXT, last_visit_time INTEGER)")
        connection.executemany("INSERT INTO urls VALUES (?, ?, ?)", rows)
        connection.commit()
    finally:
        connection.close()


def run_browser(profile: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BROWSER_SCRIPT), str(profile)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_chromium_collector_is_clean_for_unrelated_history(tmp_path: Path) -> None:
    profile = tmp_path / "Default"
    profile.mkdir(parents=True)
    make_history(profile / "History", [("https://docs.example.org/", "Documentation", 0)])
    result = run_browser(tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["finding_count"] == 0


def test_chromium_collector_finds_history_and_service_worker(tmp_path: Path) -> None:
    profile = tmp_path / "Default"
    service_worker = profile / "Service Worker" / "ScriptCache"
    service_worker.mkdir(parents=True)
    make_history(profile / "History", [("https://lucideon.top/?ga=G-0VL3ZSBXDH", "Proxy", 13400000000000000)])
    (service_worker / "entry").write_text("cached origin wisp.breadarchive.dpdns.org", encoding="utf-8")
    result = run_browser(tmp_path)
    assert result.returncode == 1, result.stderr
    payload = json.loads(result.stdout)
    evidence_types = {finding["evidence_type"] for finding in payload["findings"]}
    assert evidence_types == {"browser_history", "service_worker_or_cache"}


def test_chromium_collector_missing_profile_is_failure(tmp_path: Path) -> None:
    result = run_browser(tmp_path / "missing")
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "collection_failure"
