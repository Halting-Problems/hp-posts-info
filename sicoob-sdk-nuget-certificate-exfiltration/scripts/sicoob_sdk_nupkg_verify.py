#!/usr/bin/env python3
"""Download and verify Sicoob.Sdk NuGet artifacts against incident indicators."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path


PACKAGE_ID = "sicoob.sdk"
DISPLAY_PACKAGE_ID = "Sicoob.Sdk"
NUGET_FLAT_CONTAINER = "https://api.nuget.org/v3-flatcontainer"
REGISTRATION_INDEX = "https://api.nuget.org/v3/registration5-gz-semver2/sicoob.sdk/index.json"
VERSIONS = ["1.0.0", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4"]
MALICIOUS_VERSIONS = {"2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4"}
EXPECTED_SHA256 = {
    "1.0.0": "87b66028e491573b787ee00bc81916241047e035d152dfbf4807b57c1bbbb043",
    "2.0.0": "7d2332e76c266509cdec8b552ccc839f50c28e6b01070071257bd3f57d1d9da2",
    "2.0.1": "f0dff53969080584560b2971411415bdf9064d5a5a50185c4ae018943e7d5cbe",
    "2.0.2": "94eb8da6703dd073184015c9e3cb34e9b6153fc499c9cb1a7db6e4361ec349dd",
    "2.0.3": "ac9dc55f13d973e05865e9674c8b8e6744e7fbfca3355199b292f614f13ac7bc",
    "2.0.4": "190dbcafa776e8cc221106414b8fbd68252d98438c5e46b8449788fbe70316a4",
}
SENTRY_DSN = "https://d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232.ingest.de.sentry.io/4511337546317904"
SENTRY_HOST = "o4511335034847232.ingest.de.sentry.io"
STATIC_SELECTORS = [
    "cliend_id:",
    "pass:",
    "Boleto:",
    "SentrySdk",
    "CaptureMessage",
    "ReadAllBytes",
    "ToBase64String",
    SENTRY_DSN,
    SENTRY_HOST,
]


@dataclass
class VersionResult:
    version: str
    path: str
    sha256: str
    expected_sha256: str
    sha256_matches: bool
    expected_malicious: bool
    static_hits: list[str]
    dll_paths: list[str]


def fetch(url: str, destination: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "haltingproblems-sicoob-sdk-verifier/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            destination.write_bytes(response.read())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"download failed for {url}: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_bytes(data: bytes) -> str:
    return "\n".join(
        data.decode(encoding, errors="ignore")
        for encoding in ("utf-8", "utf-16le", "latin-1")
    )


def inspect_package(path: Path, version: str) -> VersionResult:
    static_hits: set[str] = set()
    dll_paths: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        if not any(name.lower().endswith(".nuspec") for name in names):
            raise RuntimeError(f"{path} has no nuspec")
        for name in names:
            if name.lower().endswith(".dll"):
                dll_paths.append(name)
                text = decode_bytes(zf.read(name))
                for selector in STATIC_SELECTORS:
                    if selector in text:
                        static_hits.add(selector)

    digest = sha256_file(path)
    expected = EXPECTED_SHA256[version]
    return VersionResult(
        version=version,
        path=str(path),
        sha256=digest,
        expected_sha256=expected,
        sha256_matches=digest == expected,
        expected_malicious=version in MALICIOUS_VERSIONS,
        static_hits=sorted(static_hits),
        dll_paths=dll_paths,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("sicoob-sdk-nupkg-verify-output"), help="Output directory for downloaded packages and JSON report.")
    parser.add_argument("--version", action="append", choices=VERSIONS, help="Version to verify; repeatable. Defaults to all known Sicoob.Sdk versions.")
    parser.add_argument("--no-download", action="store_true", help="Inspect already-downloaded packages in --output instead of downloading.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    versions = args.version or VERSIONS
    results: list[VersionResult] = []
    errors: list[str] = []

    registration_path = args.output / "sicoob.sdk.registration.json"
    if not args.no_download:
        fetch(REGISTRATION_INDEX, registration_path)

    for version in versions:
        filename = f"{PACKAGE_ID}.{version}.nupkg"
        path = args.output / filename
        url = f"{NUGET_FLAT_CONTAINER}/{PACKAGE_ID}/{version}/{filename}"
        try:
            if not args.no_download:
                fetch(url, path)
            if not path.exists():
                raise RuntimeError(f"missing local package {path}")
            result = inspect_package(path, version)
            results.append(result)
            print(f"{version}: sha256_match={result.sha256_matches} static_hits={len(result.static_hits)} malicious_expected={result.expected_malicious}")
        except Exception as exc:
            errors.append(f"{version}: {exc}")
            print(f"{version}: ERROR: {exc}", file=sys.stderr)

    report = {
        "incident": "sicoob-sdk-nuget-certificate-exfiltration",
        "package": DISPLAY_PACKAGE_ID,
        "registration_index": REGISTRATION_INDEX,
        "malicious_versions": sorted(MALICIOUS_VERSIONS),
        "sentry_host": SENTRY_HOST,
        "results": [asdict(result) for result in results],
        "errors": errors,
    }
    (args.output / "sicoob_sdk_nupkg_verify_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    failed_hash = [result.version for result in results if not result.sha256_matches]
    missing_malicious_hits = [
        result.version
        for result in results
        if result.expected_malicious and (SENTRY_HOST not in result.static_hits or "CaptureMessage" not in result.static_hits)
    ]
    if errors or failed_hash or missing_malicious_hits:
        if failed_hash:
            print(f"hash mismatches: {', '.join(failed_hash)}", file=sys.stderr)
        if missing_malicious_hits:
            print(f"malicious selector gaps: {', '.join(missing_malicious_hits)}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
