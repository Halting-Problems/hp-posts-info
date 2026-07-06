---
title: "Hades PyPI Graph ML Memory Scraper Campaign"
date: 2026-06-08
severity: "critical"
tags:
  - supply-chain
  - pypi
  - hades
  - credential-theft
summary: "StepSecurity reported the Hades campaign across graph ML and bioinformatics PyPI packages, using Python import hooks to download Bun v1.3.14, run _index.js, scrape secrets across Linux/macOS/Windows runners, plant developer-tooling persistence, and create GitHub exfiltration repositories."
sourceCount: 1
---

## Executive Summary

StepSecurity reported the Hades campaign across graph ML and bioinformatics PyPI packages, using Python import hooks to download Bun v1.3.14, run _index.js, scrape secrets across Linux/macOS/Windows runners, plant developer-tooling persistence, and create GitHub exfiltration repositories.

This folder ports older Astro-era supply-chain coverage into the canonical `hp-posts-info` authoring shape so the Next.js/Postgres importer can serve it. The current status is `needs_review`: the source-backed indicators are captured, but the pass intentionally does not claim fresh artifact diffing beyond the cited primary research.

## Key Facts

* **Affected assets:** bramin, cmd2func, coolbox, dynamo-release, embiggen, ensmallen, executor-engine, executor-http, funcdesc, gpsea, magique, magique-ai ....
* **Execution trigger:** Python package import hook embedded in __init__.py locates _index.js, downloads Bun, and runs the JavaScript payload.
* **Credential risk:** GitHub, OIDC, cloud, package-registry, and developer credentials reachable from impacted CI or developer environments.
* **Relationship:** migrated from the older Astro blog supply-chain roundup into a standalone Next.js/Postgres-ready incident folder.

## Defender Handling

Run the included scope scanner over repository exports, package caches, CI logs, and endpoint telemetry. Treat matches in live dependency manifests, lockfiles, workflow definitions, or runner process/network logs as exposure signals until the owning team confirms whether the malicious artifact actually executed.

## Open Questions

This migration captures coverage and source-backed selectors. Before marking publish-ready, perform fresh artifact diffing, validate current package/action cleanup status, and reconcile exact downstream victim counts from direct maintainer or platform sources.

## Sources

1. [StepSecurity primary research](https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages). **Role:** PRIMARY_RESEARCH **Impact:** Primary source for affected assets, execution trigger, payload behavior, and published IOCs.
