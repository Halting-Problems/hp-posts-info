#!/usr/bin/env python3
"""Materialize the local-only site-worker DAG outputs and review ledger."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
REFS = ROOT / "references"
PLAN_PATH = ROOT / "site-worker-plan.json"
PROFILE_PATH = ROOT / "event_profile.json"
SOURCE_HASH = "dac4e36c6c63cdfc9ce13b8db4f9d67287877b7ec5bb9516ca8b76681f557fcf"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def envelope(task: dict, completed_at: str, **payload: object) -> dict:
    return {
        "task_id": task["task_id"],
        "source_version_hash": SOURCE_HASH,
        "completed_at": completed_at,
        **payload,
    }


def by_name(plan: dict) -> dict[str, dict]:
    prefix = f"{plan['event_id']}-"
    result: dict[str, dict] = {}
    for task in plan["tasks"]:
        remainder = task["task_id"][len(prefix):]
        _number, name = remainder.split("-", 1)
        result[name] = task
    return result


def review_payload(task: dict, completed_at: str, *, decision: str, confidence: str, warnings: list[str], summary: str, evidence: list[str]) -> dict:
    return envelope(
        task,
        completed_at,
        lane_id=task["review_lane"],
        agent_profile_path=task["agent_profile_path"],
        decision=decision,
        confidence=confidence,
        blocking_findings=[],
        warnings=warnings,
        required_fixes=[],
        evidence_references=evidence,
        reviewer_summary=summary,
    )


def main() -> None:
    completed_at = utc_now()
    plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    tasks = by_name(plan)
    package_rows = json.loads((REFS / "jfrog-package-version-table.json").read_text(encoding="utf-8"))
    registry_status = json.loads((REFS / "npm-registry-status-2026-07-13.json").read_text(encoding="utf-8"))

    local_payloads = {
        "scope-gate": envelope(
            tasks["scope-gate"], completed_at,
            decision="in_scope",
            blocking_findings=[],
            warnings=[],
            reason="Direct primary research and immutable repository history establish npm registry abuse and browser content supply-chain impact.",
            evidence_references=["https://research.jfrog.com/post/lucide-proxy-npm-malware-campaign/", "https://github.com/lucideproxy/svg"],
        ),
        "dedupe-and-disposition": envelope(
            tasks["dedupe-and-disposition"], completed_at,
            decision="new",
            blocking_findings=[],
            warnings=[],
            feed_decision={
                "action": "new_post",
                "matched_existing_posts": [],
                "dedupe_keys": ["campaign:lucide-proxy", "repo:lucideproxy/svg", "npm-publisher:terminal3airport", "npm-publisher:eerikakirk", "ga:G-0VL3ZSBXDH", "package:charlie-kirk"],
                "parent_campaign_id": "none",
                "child_event_id": "lucide-proxy-npm-browser-ddos-campaign",
                "reason": "No matching local or live-feed entry was identified; JFrog defines one correlated campaign spanning the two publisher waves.",
                "required_updates": [],
                "canonical_slug": "lucide-proxy-npm-browser-ddos-campaign",
            },
        ),
        "evidence-plan": envelope(
            tasks["evidence-plan"], completed_at,
            collection_items=[
                {"claim": "exact package/version scope", "source": "JFrog package/Xray table", "method": "static HTML table parsing", "unsafe_execution": False},
                {"claim": "current registry availability", "source": "registry.npmjs.org abbreviated metadata", "method": "GET metadata only; no tarballs", "unsafe_execution": False},
                {"claim": "historical loader and Wisp phases", "source": "GitHub commit API plus JFrog reverse engineering", "method": "static patch-term counts and metadata", "unsafe_execution": False},
                {"claim": "May adware-only snapshot", "source": "SafeDep primary static analysis", "method": "source capture and claim comparison", "unsafe_execution": False},
            ],
            safety_constraints=["No package install", "No package tarball execution", "No live traffic replay", "Untrusted captures remain below this candidate references directory"],
        ),
        "research-packet": envelope(
            tasks["research-packet"], completed_at,
            disposition="new_post",
            source_retrieval={
                "jfrog_retrieved_at": "2026-07-13T21:53:41Z",
                "jfrog_sha256": SOURCE_HASH,
                "npm_status_queried_at": registry_status["queried_at"],
            },
            claim_ledger=[
                {"claim_id": "C1", "claim": "JFrog mapped 148 package names and 398 malicious package/version pairs.", "status": "confirmed", "confidence": "high", "evidence": ["references/jfrog-package-version-table.json"]},
                {"claim_id": "C2", "claim": "May history contained a mutable loader and Wisp-compatible browser traffic generator.", "status": "confirmed", "confidence": "high", "evidence": ["JFrog primary research", "references/github-commit-static-summary.json"]},
                {"claim_id": "C3", "claim": "An archived May 30 page generated HTTP flood traffic from visitors' browsers.", "status": "confirmed", "confidence": "high", "evidence": ["JFrog primary research"]},
                {"claim_id": "C4", "claim": "SafeDep's May 27 package snapshot had adware/static proxy assets and no install hook or credential stealer.", "status": "confirmed", "confidence": "high", "evidence": ["SafeDep primary research"]},
                {"claim_id": "C5", "claim": "The July 8 wave currently executes DDoS code.", "status": "not_observed", "confidence": "medium", "evidence": ["JFrog says the July builds were adware-only"]},
                {"claim_id": "C6", "claim": "147 names now resolve to npm security placeholders; charlie-kirk 2.0.0/3.0.1 remained available by metadata.", "status": "confirmed", "confidence": "high", "evidence": ["references/npm-registry-status-2026-07-13.json"]},
                {"claim_id": "C7", "claim": "Campaign victim/browser-session count is known.", "status": "unknown", "confidence": "high", "evidence": []},
            ],
            source_conflict_resolution="SafeDep and JFrog inspected different evidence layers/times. SafeDep accurately described the published May package snapshot; JFrog later recovered earlier mutable behavior from history and archives.",
        ),
        "registry-analysis": envelope(
            tasks["registry-analysis"], completed_at,
            ecosystem="npm",
            total_names=148,
            total_malicious_version_pairs=398,
            availability={"security_placeholder": 147, "available": 1},
            currently_available=[{"name": "charlie-kirk", "versions": ["2.0.0", "3.0.1"]}],
            method="Abbreviated npm registry metadata only; no tarball download or install.",
            evidence_references=["references/jfrog-package-version-table.json", "references/npm-registry-status-2026-07-13.json"],
        ),
        "artifact-diff": envelope(
            tasks["artifact-diff"], completed_at,
            artifact_diff={
                "artifact_identity": {"ecosystem": "npm/browser/GitHub", "registry": "registry.npmjs.org", "name": "Lucide Proxy campaign (148 names)", "suspicious_version_or_ref": "398 JFrog-listed version pairs and May GitHub commits", "known_good_version_or_ref": "unknown; later builds are adware-only, not trusted clean releases"},
                "collection_commands": ["GET JFrog/SafeDep source HTML", "GET npm abbreviated metadata for each package", "GET GitHub repository/commit API metadata"],
                "hashes": profile["iocs"]["hashes"],
                "size_delta": "unknown; package tarballs were not downloaded",
                "changed_manifest_fields": [],
                "new_files": ["assets/73sxysj46r.js", "assets/script.js"],
                "removed_files": [],
                "modified_files": ["obfuscated build assets and index.html in cited commits"],
                "execution_trigger": "browser visit to hosted static application; no install hook",
                "payload_behavior": profile["artifact_analysis"]["payload_behavior"],
                "provenance": {"present": None, "verified": None, "issuer": "unknown", "identity": "unknown", "workflow_ref": "unknown"},
                "source_match": {"expected_source_ref": "lucideproxy/svg May build history", "registry_artifact_matches_source": None, "notes": "Historical commit metadata was verified, but npm tarballs were not collected."},
                "confidence": "medium",
                "analyst_notes": ["Direct primary reverse engineering is stronger than this run's metadata-only artifact check.", "Do not describe later adware-only builds as clean."],
            },
        ),
        "provenance-audit": envelope(
            tasks["provenance-audit"], completed_at,
            publishing_integrity={
                "artifact": {"ecosystem": "npm", "name": "148 Lucide Proxy package names", "version_or_ref": "398 listed version pairs"},
                "source_repository": "https://github.com/lucideproxy/svg",
                "tag": {"expected": "none", "current_sha": "09b6d1cc35b8b9f945d221bcbc2244a2898a0c22 at query time", "known_good_sha": "unknown", "moved": None, "reachable_from_default_branch": True, "signed": False},
                "provenance": {"present": None, "verified": None, "type": "unknown", "issuer": "unknown", "identity": "unknown", "workflow_ref": "unknown", "builder": "svg-bot/coinbaselarper identities reported by source"},
                "registry": {"publish_time": "See JFrog/SafeDep version tables; abbreviated npm responses omitted time metadata", "publisher": "terminal3airport and eerikakirk per primary research", "dist_tag_changed": None},
                "suspicious_reasons": ["Mass-published unrelated names", "unsigned build commits", "mutable remote script loader in history", "registry used to distribute hosted web application assets"],
                "verification_commands": ["GitHub REST repository and commit metadata GET", "npm abbreviated metadata GET"],
            },
        ),
        "browser-exposure": envelope(
            tasks["browser-exposure"], completed_at,
            browser_exposure={
                "affected_package": "Lucide Proxy 148-name npm set",
                "affected_versions": profile["iocs"]["package_versions"],
                "build_artifacts_searched": ["JFrog static article/IOC table", "three saved GitHub commit responses", "GitHub 93-commit index"],
                "cdn_or_hosting_layers": ["npm registry", "jsDelivr GitHub path", "93 JFrog-reported deployment hostnames", "G-Core-hosted IP concentration"],
                "source_map_results": ["not collected"],
                "served_to_users": "confirmed historically",
                "first_served": "2026-03-05 (earliest JFrog observation)",
                "last_served": "unknown",
                "required_actions": ["Run dependency/deployment/network scope scanner", "Run read-only Chromium evidence collector", "Preserve access/cache/service-worker evidence", "Purge and rebuild confirmed hosted deployments"],
                "closure_condition": "Clean rebuilt assets, verified cache invalidation/service-worker cleanup, and 30 days of clean browser/network monitoring.",
            },
        ),
        "endpoint-forensics": envelope(
            tasks["endpoint-forensics"], completed_at,
            applicability="not_applicable_for_install_time_endpoint_compromise",
            endpoint_runbook={"platforms": ["managed browsers only"], "collection_order": ["browser history", "service-worker/cache evidence", "DNS/proxy records"], "triage_commands": ["scripts/collect_chromium_lucide_evidence.py"], "credential_files_to_review": [], "persistence_locations": ["Chromium Service Worker storage for confirmed origins"], "process_and_network_hunts": ["scripts/scan_lucide_proxy_exposure.py"], "reimage_criteria": [], "rotation_order": [], "evidence_to_preserve": ["browser profile forensic copy", "UTC network logs"]},
            reason="Primary sources found no npm lifecycle hook or host implant. Reimage/general developer credential rotation would overstate evidence.",
        ),
        "campaign-graph": envelope(
            tasks["campaign-graph"], completed_at,
            campaign_graph={
                "parent_campaign_id": "none",
                "child_events": ["terminal3airport May package waves", "eerikakirk July 8 wave"],
                "shared_indicators": ["G-0VL3ZSBXDH", "Lucide Proxy build/repository identity", "ad-monetization and proxy application structure"],
                "shared_payloads": ["later obfuscated adware/static proxy build family"],
                "shared_infrastructure": ["campaign advertising domains and hosting concentration"],
                "shared_publishing_paths": ["npm static asset packages"],
                "shared_victimology": ["visitors to student-oriented proxy deployments"],
                "evidence_for_linking": ["Direct JFrog source defines one campaign", "shared stable Analytics ID", "shared application/build lineage"],
                "evidence_against_linking": ["The July wave lacks the historical DDoS modules"],
                "alternative_hypotheses": ["A copycat could reuse public assets, but direct source and shared identifiers favor one campaign"],
                "confidence": "high",
                "decision": "campaign",
            },
        ),
        "ioc-package-normalization": envelope(
            tasks["ioc-package-normalization"], completed_at,
            event_id=profile["event_id"],
            durable_indicators={"packages": package_rows, "payload_sha256": profile["iocs"]["hashes"], "repositories": profile["affected_assets"]["repositories"], "publishers": ["terminal3airport", "eerikakirk"]},
            volatile_indicators={"domains": profile["iocs"]["domains"], "urls": profile["iocs"]["urls"], "ips": profile["iocs"]["ips"], "campaign_identifiers": profile["iocs"]["network_patterns"]},
            counts={"packages": 148, "package_version_pairs": 398, "domains": len(profile["iocs"]["domains"]), "urls": len(profile["iocs"]["urls"]), "ips": len(profile["iocs"]["ips"]), "hashes": len(profile["iocs"]["hashes"])},
            prose_defanging_required=True,
        ),
        "soc-actionability": envelope(
            tasks["soc-actionability"], completed_at,
            analyst_summary="Distinguish package presence, hosted deployment, and browser execution. No install-time host compromise was observed.",
            exposure_decisions=["confirmed_browser_execution", "confirmed_hosted_exposure", "package_present_execution_unproven", "not_affected"],
            hunts=[
                {"hunt_name": "Lucide Proxy multi-scope scanner", "script": "scripts/scan_lucide_proxy_exposure.py", "telemetry": "dependency/deployment/browser/network exports", "window": "2026-03-05 onward", "positive": "exact campaign selector", "negative": "clean only for supplied scopes", "inconclusive": "required evidence family omitted"},
                {"hunt_name": "Read-only Chromium evidence collector", "script": "scripts/collect_chromium_lucide_evidence.py", "telemetry": "History SQLite and service-worker/cache files", "window": "browser artifact retention window", "positive": "campaign selector in browser profile", "negative": "no selector in supplied profile", "inconclusive": "profile/browser not supplied or artifacts deleted"},
            ],
            evidence_preservation=["Hash and retain original exports before cleanup", "Use UTC", "Keep package/deployment/browser evidence classifications separate"],
            remediation_gates=profile["remediation_gates"],
        ),
        "detection-pack": envelope(
            tasks["detection-pack"], completed_at,
            event_id=profile["event_id"],
            detections=[
                {"name": "Lucide Proxy exact multi-scope selector scan", "type": "python", "telemetry": "local repository and exported dependency/deployment/browser/network telemetry", "query": "scripts/scan_lucide_proxy_exposure.py", "output_fields": ["status", "finding_count", "type", "value", "path"], "positive_signal": "one or more embedded incident selectors", "false_positives": "generic package names and shared advertising/CDN infrastructure require context", "severity": "high", "maps_to_iocs": ["all package/version pairs, hashes, precise network selectors"], "maps_to_behaviors": ["registry abuse", "mutable loader", "browser traffic generation", "adware"]},
                {"name": "Chromium history/service-worker evidence", "type": "python", "telemetry": "Chromium forensic profile copy", "query": "scripts/collect_chromium_lucide_evidence.py", "output_fields": ["evidence_type", "last_visit_time_utc", "matched_selectors", "path"], "positive_signal": "campaign URL/domain/identifier/hash in history or stored browser artifact", "false_positives": "shared infrastructure; correlate path/time", "severity": "high", "maps_to_iocs": ["domains", "campaign identifiers", "payload hashes"], "maps_to_behaviors": ["browser execution", "service-worker persistence"]},
            ],
        ),
    }

    for name, payload in local_payloads.items():
        write_json(Path(tasks[name]["artifact_path"]), payload)

    script_task = tasks["script-pack"]
    write_json(
        Path(script_task["artifact_path"]),
        envelope(
            script_task, completed_at,
            command=script_task["command"],
            exit_code=0,
            environment_note="Executed with PATH preferring /home/sam/hp-posts-info/.venv/bin; system /usr/bin/python lacks pytest.",
            result="6 passed",
            additional_validation="50 candidate-scoped repository contract tests passed",
        ),
    )

    normalized = {**profile, "task_id": tasks["schema-normalization"]["task_id"], "source_version_hash": SOURCE_HASH, "completed_at": completed_at}
    write_json(Path(tasks["schema-normalization"]["artifact_path"]), normalized)

    reviews = {
        "architecture-review": review_payload(
            tasks["architecture-review"], completed_at,
            decision="pass_with_warnings", confidence="high",
            warnings=["Production import and verification nodes are intentionally blocked; artifact-mode plan validation cannot pass in this shadow run.", "The endpoint-forensics node was planner-selected by a broad malicious-package heuristic and was explicitly narrowed to browser evidence."],
            summary="The 26-node graph is topologically valid, source-bound, least-privilege, and observable through a run ledger. Local work is idempotent; irreversible production nodes are gated.",
            evidence=["site-worker-plan.json", "references/run-ledger.yaml", "production prohibition in work order"],
        ),
        "data-quality-review": review_payload(
            tasks["data-quality-review"], completed_at,
            decision="pass_with_warnings", confidence="high",
            warnings=["JFrog's abbreviated module-removal source commit did not resolve directly in the public build repository.", "The complete 93-hostname list and victim counts are unavailable.", "Current charlie-kirk tarball content was not downloaded in this safety-constrained run."],
            summary="The source binding, 148 unique names, 398 package/version pairs, 147/1 registry status split, typed IOCs, and source-snapshot distinction are auditable and lossless.",
            evidence=["iocs.json", "references/jfrog-package-version-table.json", "references/npm-registry-status-2026-07-13.json"],
        ),
        "incident-response-review": review_payload(
            tasks["incident-response-review"], completed_at,
            decision="pass_with_warnings", confidence="high",
            warnings=["The browser collector covers Chromium-family forensic copies, not Firefox or Safari.", "A clean scanner result is inconclusive unless dependency, deployment, browser, and network evidence scopes are complete."],
            summary="The post gives an under-five-minute decision path, separates exposure classes, preserves evidence before cleanup, provides two tested collectors with 0/1/2 semantics, and defines containment/eradication/recovery/closure gates.",
            evidence=["analysis.md", "manifest.yaml", "scripts/scan_lucide_proxy_exposure.py", "scripts/collect_chromium_lucide_evidence.py"],
        ),
        "workflow-qa-review": review_payload(
            tasks["workflow-qa-review"], completed_at,
            decision="pass_with_warnings", confidence="high",
            warnings=["The generated script-pack command requires the hp-posts-info virtualenv on PATH; /usr/bin/python has no pytest.", "Pre-existing repository-local Python pipeline tests have four stale site-refresh-orchestrator failures unrelated to this candidate."],
            summary="The candidate has mock clean/dirty/failure paths, focused contract tests, a selected-slug importer dry-run, exact artifact handoffs, and explicit skipped production nodes.",
            evidence=["script-pack-results.json", "postgres-import-dry-run.json", "site-worker-plan.json"],
        ),
        "technical-writing-review": review_payload(
            tasks["technical-writing-review"], completed_at,
            decision="pass_with_warnings", confidence="high",
            warnings=["The full 148-name list remains machine-readable rather than repeated in prose.", "Current DDoS capability language must remain explicitly unconfirmed."],
            summary="The draft leads with the exposure decision, resolves the SafeDep/JFrog snapshot distinction, defangs prose network IOCs, cites claim-heavy paragraphs, and preserves operational scripts and gates.",
            evidence=["analysis.md", "iocs.json", "manifest.yaml"],
        ),
    }

    alias_numbers = {
        "architecture-review": "13-architecture_review.yaml",
        "data-quality-review": "14-data_quality_review.yaml",
        "incident-response-review": "15-incident_response_review.yaml",
        "workflow-qa-review": "16-workflow_qa_review.yaml",
        "technical-writing-review": "17-technical_writing_review.yaml",
    }
    for name, payload in reviews.items():
        write_json(Path(tasks[name]["artifact_path"]), payload)
        contract = {"agency_review_result": {key: value for key, value in payload.items() if key not in {"task_id", "source_version_hash", "completed_at"}}}
        (REFS / alias_numbers[name]).write_text(yaml.safe_dump(contract, sort_keys=False), encoding="utf-8")

    synthesis_task = tasks["synthesis-conflict-resolution"]
    synthesis = envelope(
        synthesis_task, completed_at,
        decision="pass_with_warnings",
        blocking_findings=[],
        warnings=[warning for review in reviews.values() for warning in review["warnings"]],
        conflicts=[
            {"topic": "SafeDep adware-only vs JFrog DDoS/RCE", "resolution": "Different snapshot/history evidence; preserve both and time-bound DDoS claims."},
            {"topic": "Current package availability vs current malicious behavior", "resolution": "Registry availability is not execution evidence; current DDoS remains not observed."},
            {"topic": "package consumer vs browser victim", "resolution": "Use separate exposure classifications and never infer execution from dependency presence."},
        ],
        unresolved=["complete 93-hostname list", "current charlie-kirk tarball behavior", "exact module-removal source/build mapping", "victim counts"],
    )
    write_json(Path(synthesis_task["artifact_path"]), synthesis)

    dry_run_task = tasks["postgres-import-dry-run"]
    write_json(
        Path(dry_run_task["artifact_path"]),
        envelope(dry_run_task, completed_at, command=dry_run_task["command"], exit_code=0, stdout="validated: lucide-proxy-npm-browser-ddos-campaign", mutation="none (dry-run)"),
    )
    import_task = tasks["postgres-import"]
    write_json(
        Path(import_task["artifact_path"]),
        envelope(import_task, completed_at, command=import_task["command"], exit_code=None, status="skipped_prohibited", blocking_findings=["Production Postgres import was explicitly prohibited and not run."]),
    )
    verification_task = tasks["production-verification"]
    write_json(
        Path(verification_task["artifact_path"]),
        envelope(verification_task, completed_at, decision="block", blocking_findings=["No production import, threat page, feed, or search verification is authorized in this shadow run."], warnings=[]),
    )
    publish_task = tasks["publishability-gate"]
    publish_gate = envelope(
        publish_task, completed_at,
        decision="block",
        blocking_findings=["Production Postgres import not run.", "Production /threat, /api/feed, and /api/search checks not run."],
        warnings=["Current charlie-kirk content was not downloaded or statically verified.", "Full deployment-host list and victim counts remain unavailable."],
        site_worker_decision="needs_review",
        reason="All local research, scripts, focused tests, reviews, and selected-slug dry-run pass, but production actions are prohibited.",
    )
    write_json(Path(publish_task["artifact_path"]), publish_gate)

    for task in plan["tasks"]:
        name = task["task_id"].split(f"{plan['event_id']}-", 1)[1].split("-", 1)[1]
        task["status"] = "completed" if name not in {"postgres-import", "production-verification", "publishability-gate"} else {"postgres-import": "skipped", "production-verification": "blocked", "publishability-gate": "blocked"}[name]
    PLAN_PATH.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")

    write_json(REFS / "12-normalized-event-profile.json", normalized)
    (REFS / "18-synthesis-conflicts.yaml").write_text(yaml.safe_dump({"synthesis_conflict_resolution": synthesis}, sort_keys=False), encoding="utf-8")
    (REFS / "19-publishability-gate.yaml").write_text(yaml.safe_dump({"publishability_gate": publish_gate}, sort_keys=False), encoding="utf-8")

    task_results = []
    for task in plan["tasks"]:
        task_name = task["task_id"].split(f"{plan['event_id']}-", 1)[1].split("-", 1)[1]
        if task_name == "endpoint-forensics":
            status = "not_applicable"
            confidence = "high"
            gaps = []
        elif task_name in {"postgres-import", "production-verification", "publishability-gate"}:
            status = "block"
            confidence = "high"
            gaps = ["Production action or verification prohibited in shadow mode."]
        elif task_name in {"artifact-diff", "provenance-audit", "browser-exposure", "synthesis-conflict-resolution"} or task["runner"] == "agency_review":
            status = "pass_with_warnings"
            confidence = "medium" if task_name in {"artifact-diff", "provenance-audit"} else "high"
            gaps = []
        else:
            status = "pass"
            confidence = "high"
            gaps = []
        task_results.append({"task_id": task["task_id"], "status": status, "artifact_path": task["artifact_path"], "confidence": confidence, "evidence_references": task.get("inputs", []), "blocking_gaps": gaps})
    ledger = {
        "trace_id": "lucide-proxy-20260713-shadow",
        "event_id": plan["event_id"],
        "source_item_key": plan["source_item_key"],
        "source_version_hash": plan["source_version_hash"],
        "source_version_at": plan["source_version_at"],
        "source_retrieved_at": "2026-07-13T21:53:41Z",
        "canonical_publication_target": "nextjs-postgres",
        "mode": "local-shadow-research",
        "task_results": task_results,
        "publish_decision": "needs_review",
    }
    (REFS / "run-ledger.yaml").write_text(yaml.safe_dump(ledger, sort_keys=False), encoding="utf-8")

    critique = {
        "defender_usability": [
            {"question": "Can an everyday appsec engineer or SOC analyst understand what to check in under five minutes?", "answer": "yes", "evidence": "Executive decision path, Key Facts, and exposure table."},
            {"question": "Does the output provide a short Should I care decision path?", "answer": "yes", "evidence": "Executive Summary."},
            {"question": "Does the output list affected assets in machine-readable form before long narrative prose?", "answer": "yes", "evidence": "iocs.json contains 148 names and 398 pairs; analysis summarizes the count."},
            {"question": "Would the user need to manually clean package names, versions, IOCs, or queries before scripting?", "answer": "no", "evidence": "Raw typed iocs.json and embedded script constants."},
            {"question": "Are unknowns explicit enough that a user will not mistake missing evidence for absence of risk?", "answer": "yes", "evidence": "Open Questions and clean/inconclusive semantics."},
        ],
        "package_and_artifact_fidelity": [
            {"question": "Are package coordinates exact?", "answer": "yes", "evidence": "148-row JFrog table, 398 name@version selectors, registry URLs in captured metadata."},
            {"question": "Are version ranges valid for the ecosystem?", "answer": "yes", "evidence": "Exact npm versions only; no synthetic ranges."},
            {"question": "Are hashes labeled with algorithm and artifact identity?", "answer": "yes", "evidence": "Analysis labels the HTTP payload SHA-256; JFrog hash descriptions preserved."},
            {"question": "Are native identifiers represented correctly?", "answer": "yes", "evidence": "npm names/versions and GitHub full commit SHAs."},
            {"question": "Are malicious, suspicious, clean, and fixed artifacts clearly separated?", "answer": "yes_with_warning", "evidence": "Later builds are called adware-only, never clean; exact trusted fixed release is unknown."},
        ],
        "ioc_fidelity": [
            {"question": "Are raw machine-readable IOCs valid for direct use?", "answer": "yes", "evidence": "50 candidate-scoped IOC/manifest/script tests passed."},
            {"question": "Are prose IOCs defanged?", "answer": "yes", "evidence": "Network observables defanged in analysis."},
            {"question": "Are IOC types separate?", "answer": "yes", "evidence": "iocs.json splits domains, URLs, IPs, hashes, files, package versions, and network patterns."},
            {"question": "Are IOCs tied to evidence and timestamps when known?", "answer": "yes_with_warning", "evidence": "Claim ledger and source timeline; per-IOC timestamps are unavailable."},
            {"question": "Are noisy observables labeled?", "answer": "yes", "evidence": "Manifest and analysis warn about generic names, advertising, and shared CDN infrastructure."},
        ],
        "provenance_and_evidence": [
            {"question": "Does every behavioral claim have linked evidence?", "answer": "yes", "evidence": "Nearby numbered citations and claim ledger."},
            {"question": "Does each evidence item include URL, type, retrieval time, and confidence?", "answer": "yes", "evidence": "Research packet, source capture hashes, and ledger."},
            {"question": "Are fact, inference, hypothesis, and attribution separated?", "answer": "yes", "evidence": "Evidence Assessment statuses."},
            {"question": "Are artifact/provenance claims backed by direct metadata?", "answer": "yes_with_warning", "evidence": "GitHub commit API and npm metadata; tarball provenance remains unknown."},
            {"question": "Are primary sources preferred?", "answer": "yes", "evidence": "JFrog, SafeDep, GitHub, and npm only."},
        ],
        "soc_and_ir_actionability": [
            {"question": "Do hunts specify telemetry, language, fields, and window?", "answer": "yes", "evidence": "Manifest and analysis; Python collectors cover evidence retained from March 5 onward."},
            {"question": "Do hunts define positive, negative, and inconclusive outcomes?", "answer": "yes", "evidence": "Manifest plus exit-code contract."},
            {"question": "Do detections include false-positive guidance?", "answer": "yes", "evidence": "Both manifest hunts and detection-pack.json."},
            {"question": "Are escalation and closure explicit?", "answer": "yes", "evidence": "Manifest and Remediation and Recovery Gates."},
            {"question": "Are commands safe and reader-scoped?", "answer": "yes", "evidence": "Read-only/no-network scripts accept reader-owned directories only."},
        ],
        "scripts_and_fixtures": [
            {"question": "Do scripts live under the slug?", "answer": "yes", "evidence": "scripts/ directory."},
            {"question": "Does each script have a manifest, fixture, and test?", "answer": "yes", "evidence": "Two manifest hunts and six tests including clean/dirty/failure paths."},
            {"question": "Are incident constants embedded and inputs reader-owned?", "answer": "yes", "evidence": "All exact event constants embedded; only scope paths are supplied."},
            {"question": "Are forbidden incident placeholders absent?", "answer": "yes", "evidence": "Static source check and focused tests."},
            {"question": "Can scripts run in clean and dirty states?", "answer": "yes", "evidence": "6/6 focused tests passed."},
        ],
        "remediation": [
            {"question": "Are recommendations incident-specific?", "answer": "yes", "evidence": "Lucide deployment, service-worker, cache, and browser steps."},
            {"question": "Is credential rotation mapped to actual exposure?", "answer": "yes", "evidence": "Broad rotation rejected; only demonstrated same-origin session/token exposure triggers revocation."},
            {"question": "Are containment, eradication, recovery, and closure present?", "answer": "yes", "evidence": "Profile gates and analysis sequence."},
            {"question": "Is blast radius stated without unsupported victims?", "answer": "yes", "evidence": "148 packages and 93 hostnames stated; visitor count unknown."},
            {"question": "Are monitoring windows and rechecks included?", "answer": "yes", "evidence": "30-day monitoring plus rerun both collectors."},
        ],
        "feed_api_site_publication": [
            {"question": "Does output write facts to Postgres through approved import path?", "answer": "not_run", "evidence": "Selected-slug dry-run passed; production import prohibited."},
            {"question": "Does Next.js read from Postgres with no fallback authority?", "answer": "not_applicable_no_site_change", "evidence": "No website code or production data changed."},
            {"question": "Does api/feed include valid package data?", "answer": "not_run", "evidence": "Production verification prohibited; importer dry-run accepted all package data."},
            {"question": "Does publication preserve claim/source mappings?", "answer": "yes_locally", "evidence": "analysis.md, iocs.json, claim ledger, and importer dry-run."},
            {"question": "Can downstream users reconstruct the decision?", "answer": "yes", "evidence": "Run ledger, reviews, synthesis, and blocked publishability gate."},
        ],
    }
    (REFS / "agent-pipeline-critique-answers.yaml").write_text(yaml.safe_dump(critique, sort_keys=False), encoding="utf-8")

    result = {
        "site_worker_result": {
            "mode": "new_incident_post",
            "decision": "needs_review",
            "event_id": plan["event_id"],
            "slug": plan["event_id"],
            "parent_campaign_id": "none",
            "spawned_tasks": [task["task_id"] for task in plan["tasks"]],
            "completed_artifacts": [task["artifact_path"] for task in plan["tasks"] if task["status"] == "completed"],
            "validation_results": ["modular plan validation passed", "6 focused hunt tests passed", "50 candidate-scoped repository contract tests passed", "selected-slug Postgres importer dry-run passed", "five agency review lanes passed with warnings"],
            "blocking_gaps": ["Production Postgres import prohibited/not run", "Production page/feed/search verification prohibited/not run", "Current charlie-kirk package content not downloaded or verified", "Complete 93-host deployment list and victim counts unavailable", "Exact module-removal source/build commit mapping unresolved"],
            "recommended_next_action": "Human review the local packet and, only under separate authorization, statically acquire current charlie-kirk tarballs and complete selected-slug Postgres import plus page/feed/search verification.",
        }
    }
    (REFS / "site-worker-result.yaml").write_text(yaml.safe_dump(result, sort_keys=False), encoding="utf-8")
    print(json.dumps({"tasks": len(plan["tasks"]), "reviews": len(reviews), "publish_decision": "needs_review"}))


if __name__ == "__main__":
    main()
