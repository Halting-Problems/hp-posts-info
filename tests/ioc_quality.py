"""Semantic IOC validation helpers for hp-posts-info.

These checks keep iocs.json values deployable: they must be typed observables or
detectable selectors, not prose instructions, remediation advice, or malformed
package/version strings.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


COMPARATOR_RE = re.compile(r"(^|\s)(?:>=|<=|==|!=|~=|>|<|\^|~)\s*\S+")
PACKAGE_NAME_RE = re.compile(r"^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9][A-Za-z0-9._~+/-]*$")
PACKAGE_VERSION_RE = re.compile(
    r"^(?P<name>(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9][A-Za-z0-9._~+/-]*)"
    r"(?:@|:|==|>=|<=|>|<|~=|\s+(?:==|>=|<=|>|<|~=)?\s*)"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._*+!~:-]*)$"
)
DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
HEX_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,128}$")
SUGGESTION_RE = re.compile(
    r"^(?:audit|check|review|rotate|remove|delete|search|find|look for|investigate|monitor|ensure|verify)\s+",
    re.IGNORECASE,
)
INLINE_VERSION_RE = re.compile(
    r"(?:@[0-9]+[A-Za-z0-9._*+!~:-]*|\s+(?:==|>=|<=|>|<|~=)?\s*[0-9]+[A-Za-z0-9._*+!~:-]*)$"
)
BARE_VERSION_RE = re.compile(r"^v?\d+(?:[._-][A-Za-z0-9]+)*$")
SENTENCE_END_RE = re.compile(r"[.!?]\s*$")

IOC_LIST_FIELDS = {
    "iocs.package_versions",
    "iocs.files",
    "iocs.hashes",
    # Domains and URLs may be research references or generic service hosts.
    # They are validated as IOC data, but are not required detector selectors.
    "iocs.ips",
    "iocs.process_patterns",
    "iocs.network_patterns",
    "detection.lockfile_hunts",
    "detection.filesystem_hunts",
    "detection.process_hunts",
    "detection.network_hunts",
    "detection.ci_cd_hunts",
    "detection.registry_hunts",
}

COVERAGE_FIELDS = {
    "affected_assets.packages",
    "iocs.package_versions",
    "iocs.files",
    "iocs.hashes",
    # Research/advisory hosts and URLs are not required to be executable hunts.
    "iocs.ips",
    "iocs.process_patterns",
    "iocs.network_patterns",
}


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _values_at(data: dict, dotted_path: str) -> list[object]:
    cursor: object = data
    for part in dotted_path.split("."):
        if not isinstance(cursor, dict):
            return []
        cursor = cursor.get(part, [])
    return _as_list(cursor)


def _format_error(slug: str, field: str, value: object, reason: str) -> str:
    return f"{slug}: {field} value {value!r} is invalid: {reason}"


def _is_prose_suggestion(value: str) -> bool:
    normalized = " ".join(value.strip().split())
    if not normalized:
        return True
    if SUGGESTION_RE.search(normalized):
        return True
    words = re.findall(r"[A-Za-z]+", normalized)
    return len(words) >= 8 and SENTENCE_END_RE.search(normalized) is not None


def _validate_package_name(value: str) -> str | None:
    if BARE_VERSION_RE.fullmatch(value):
        return "package name must not be a bare version"
    if COMPARATOR_RE.search(value) or INLINE_VERSION_RE.search(value):
        return "package names must be canonical names without versions or comparators"
    if "\n" in value or "\r" in value or "\t" in value:
        return "package name must be a single-line package or product identifier"
    if " " in value:
        return None
    if not PACKAGE_NAME_RE.fullmatch(value):
        return "package name contains unsupported characters"
    return None


def _validate_package_version(value: str) -> str | None:
    if "[.]" in value or "[:]" in value:
        return "package version IOC must not be defanged"
    if value.strip().startswith((">", "<", "=", "~", "^")):
        return "package version IOC must include the package name before the version constraint"
    match = PACKAGE_VERSION_RE.fullmatch(value.strip())
    if not match:
        return "package version IOC must look like 'name@version', 'name==version', or 'name >= version'"
    if _validate_package_name(match.group("name")):
        return "package portion is not a canonical package name"
    return None


def _validate_domain(value: str) -> str | None:
    if "://" in value or "/" in value:
        return "domain IOC must not include a URL scheme or path"
    if value.startswith(("hxxp", "http")):
        return "domain IOC must be a host only, not a URL"
    if not DOMAIN_RE.fullmatch(value.replace("[.]", ".")):
        return "domain IOC does not look like a DNS name"
    return None


def _validate_url(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "URL IOC must include http(s) scheme and host"
    return None


def _validate_ip(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "IP IOC is not a valid IPv4 or IPv6 address"
    return None


def _validate_hash(value: str) -> str | None:
    if not HEX_HASH_RE.fullmatch(value):
        return "hash IOC must be a hex digest"
    return None


def _validate_file(value: str) -> str | None:
    if value.strip() != value or not value:
        return "file/path IOC must be non-empty and trimmed"
    if "\n" in value or "\r" in value or "\t" in value:
        return "file/path IOC must be a single-line selector"
    return None


def _validate_path_or_selector(value: str) -> str | None:
    if not value.strip():
        return "selector must be non-empty"
    if _is_prose_suggestion(value):
        return "IOC/detection selector appears to be prose guidance rather than a detectable value"
    return None


def _validate_value(field: str, value: object) -> str | None:
    if not isinstance(value, str):
        return "IOC values must be strings"
    value = value.strip()
    if _is_prose_suggestion(value):
        return "IOC value appears to be prose guidance rather than a detectable value"
    if field == "affected_assets.packages":
        return _validate_package_name(value)
    if field == "iocs.package_versions":
        return _validate_package_version(value)
    if field == "iocs.domains":
        return _validate_domain(value)
    if field == "iocs.urls":
        return _validate_url(value)
    if field == "iocs.ips":
        return _validate_ip(value)
    if field == "iocs.hashes":
        return _validate_hash(value)
    if field == "iocs.files":
        return _validate_file(value)
    if field in IOC_LIST_FIELDS:
        return _validate_path_or_selector(value)
    return None


def find_ioc_quality_errors(data: dict, slug: str) -> list[str]:
    """Return semantic IOC quality errors for one iocs.json document."""
    errors: list[str] = []
    affected_versions = {
        value.strip()
        for value in _values_at(data, "affected_assets.versions")
        if isinstance(value, str) and value.strip()
    }
    fields = sorted(IOC_LIST_FIELDS | {"affected_assets.packages"})
    for field in fields:
        for value in _values_at(data, field):
            if field == "iocs.ips" and isinstance(value, str) and value.strip() in affected_versions:
                errors.append(_format_error(slug, field, value, "software version must not be typed as an IP IOC"))
                continue
            reason = _validate_value(field, value)
            if reason:
                errors.append(_format_error(slug, field, value, reason))
    return errors


def _flatten_coverage_iocs(data: dict) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for field in sorted(COVERAGE_FIELDS):
        for value in _values_at(data, field):
            if isinstance(value, str) and value.strip():
                if field == "affected_assets.packages" and " " in value.strip():
                    continue
                values.append((field, value.strip()))
    return values


def _script_sources(script_paths: list[Path]) -> str:
    chunks: list[str] = []
    for script in script_paths:
        if script.exists():
            chunks.append(script.read_text(encoding="utf-8"))
    return "\n".join(chunks)


def _is_represented(value: str, source: str) -> bool:
    if value in source:
        return True
    escaped = re.escape(value)
    if escaped in source:
        return True
    return value.replace("\\", "\\\\") in source


def _package_version_parts(value: str) -> tuple[str, str] | None:
    match = PACKAGE_VERSION_RE.fullmatch(value.strip())
    if not match:
        return None
    return match.group("name"), match.group("version")


def _is_ioc_represented(field: str, value: str, source: str) -> bool:
    if _is_represented(value, source):
        return True
    if field == "iocs.package_versions":
        parts = _package_version_parts(value)
        if parts:
            package_name, version = parts
            return _is_represented(package_name, source) and _is_represented(version, source)
    return False


def find_script_coverage_errors(data: dict, script_paths: list[Path], slug: str) -> list[str]:
    """Return errors for IOC values not represented in any manifest script."""
    source = _script_sources(script_paths)
    errors: list[str] = []
    for field, value in _flatten_coverage_iocs(data):
        if _is_prose_suggestion(value):
            continue
        if not _is_ioc_represented(field, value, source):
            checked = ", ".join(str(path.relative_to(path.parent.parent)) for path in script_paths)
            errors.append(
                f"{slug}: {field} value {value!r} is not represented in manifest scripts ({checked})"
            )
    return errors
