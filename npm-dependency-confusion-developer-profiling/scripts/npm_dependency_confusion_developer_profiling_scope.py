#!/usr/bin/env python3
"""Hunt for Microsoft-tracked npm dependency-confusion developer-profiling indicators."""
import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

SLUG = "npm-dependency-confusion-developer-profiling"

PACKAGE_NAMES = [
    "@capibar.chat/ui-kit",
    "@ce-rwb/ce-tools-editor-admin",
    "@ce-rwb/ce-tools-editor-core",
    "@ce-rwb/ce-tools-editor-render",
    "@cloudplatform-single-spa/logaas",
    "@data-science/llm",
    "@payments-widget/payments-widget-sdk",
    "@sber-ecom-core/sberpay-widget",
    "@t-in-one/add_app_middleware_token",
    "@t-in-one/add_application",
    "@t-in-one/add_application_service_token",
    "@t-in-one/add_application_tid",
    "@t-in-one/application_id_storage_key_token",
    "@t-in-one/form_product_token",
    "@t-in-one/get_application_hid",
    "@t-in-one/only_difference_payload",
    "@t-in-one/prefill_bundle_data_token",
    "@t-in-one/prefill_credit_data_token",
    "@travel-autotests/npm-proto",
    "@wb-track/shared-front",
    "@wordpress/interactivity",
    "@wordpress/interactivity-js-modulepreload",
]
PACKAGE_VERSIONS = [
    "@capibar.chat/ui-kit@0.0.1-security",
    "@ce-rwb/ce-tools-editor-admin@0.0.1-security",
    "@ce-rwb/ce-tools-editor-core@0.0.1-security",
    "@ce-rwb/ce-tools-editor-render@0.0.1-security",
    "@cloudplatform-single-spa/logaas@0.0.1-security",
    "@data-science/llm@0.0.1-security",
    "@payments-widget/payments-widget-sdk@0.0.1-security",
    "@sber-ecom-core/sberpay-widget@0.0.1-security",
    "@t-in-one/add_app_middleware_token@0.0.1-security",
    "@t-in-one/add_application@0.0.1-security",
    "@t-in-one/add_application_service_token@0.0.1-security",
    "@t-in-one/add_application_tid@0.0.1-security",
    "@t-in-one/application_id_storage_key_token@0.0.1-security",
    "@t-in-one/form_product_token@0.0.1-security",
    "@t-in-one/get_application_hid@0.0.1-security",
    "@t-in-one/only_difference_payload@0.0.1-security",
    "@t-in-one/prefill_bundle_data_token@0.0.1-security",
    "@t-in-one/prefill_credit_data_token@0.0.1-security",
    "@travel-autotests/npm-proto@0.0.1-security",
    "@wb-track/shared-front@0.0.1-security",
    "@wordpress/interactivity@0.0.1-security",
    "@wordpress/interactivity-js-modulepreload@0.0.1-security",
]
DOMAINS = ["oob.moika.tech"]
HEADERS = ["X-Secret"]
FLAGS = ["RECON_ONLY"]
PROCESS_TERMS = [
    "postinstall",
    "npm lifecycle hook",
    "dependency confusion",
    "developer environment fingerprinting",
    "credential reconnaissance",
    "developer context",
    "environment variables",
    "hostname",
]
EXCLUDED_DIRS = {".git", "node_modules", "dist", "build", "coverage", ".cache", ".next", ".turbo", "vendor", "tmp", "temp"}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".class", ".jar"}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    category: str
    indicator: str
    evidence: str


INDICATORS: list[tuple[str, str]] = []
for value in PACKAGE_VERSIONS:
    INDICATORS.append(("package_version", value))
for value in PACKAGE_NAMES:
    INDICATORS.append(("package", value))
for value in DOMAINS:
    INDICATORS.append(("domain", value))
for value in HEADERS:
    INDICATORS.append(("header", value))
for value in FLAGS:
    INDICATORS.append(("flag", value))
for value in PROCESS_TERMS:
    INDICATORS.append(("process", value))


def _read_text(path: Path) -> str | None:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeError):
        return None


def _iter_files(roots: Iterable[Path]) -> Iterable[Path]:
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            yield root
            continue
        for current, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for filename in files:
                yield Path(current) / filename


def _first_line_with(text: str, needle: str) -> tuple[int, str]:
    needle_lower = needle.lower()
    for idx, line in enumerate(text.splitlines(), start=1):
        if needle_lower in line.lower():
            return idx, line.strip()
    return 1, text[:200].strip().replace("\n", " ")


def scan_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for path in _iter_files(paths):
        text = _read_text(path)
        if not text:
            continue
        lowered = text.lower()
        for category, indicator in INDICATORS:
            needle = indicator.lower()
            contextual_package_match = None
            if category == "package_version":
                package, version = indicator.rsplit("@", 1)
                contextual_package_match = re.search(
                    rf'"{re.escape(package)}"\s*:\s*"{re.escape(version)}"',
                    text,
                    re.IGNORECASE,
                )
            if needle in lowered or contextual_package_match:
                line, evidence = _first_line_with(
                    text,
                    indicator if needle in lowered else indicator.rsplit("@", 1)[0],
                )
                key = (str(path), category, indicator)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        path=str(path),
                        line=line,
                        category=category,
                        indicator=indicator,
                        evidence=evidence,
                    )
                )
    findings.sort(key=lambda item: (item.path, item.line, item.category, item.indicator))
    return findings


def _build_report(findings: list[Finding]) -> str:
    if not findings:
        return "No Microsoft-tracked dependency-confusion indicators found."
    lines = [f"{len(findings)} indicator hit(s) across {len({f.path for f in findings})} file(s):"]
    for finding in findings:
        lines.append(
            f"- {finding.path}:{finding.line} [{finding.category}] {finding.indicator} :: {finding.evidence}"
        )
    return "\n".join(lines)


def _write_output(output_path: Path, findings: list[Finding]) -> None:
    payload = {
        "slug": SLUG,
        "finding_count": len(findings),
        "findings": [asdict(finding) for finding in findings],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=["."], help="Repository or log export paths to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    parser.add_argument("--output", type=Path, help="Optional path to write a JSON report")
    args = parser.parse_args(argv)

    roots = [Path(path) for path in args.paths]
    findings = scan_paths(roots)
    if args.output:
        _write_output(args.output, findings)

    if args.json:
        print(json.dumps({"slug": SLUG, "finding_count": len(findings), "findings": [asdict(f) for f in findings]}, indent=2, sort_keys=True))
    else:
        print(_build_report(findings))

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
