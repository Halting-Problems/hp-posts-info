---
title: "Mini Shai-Hulud SAP npm Bun Runtime Payloads"
date: 2026-04-29
severity: "critical"
tags:
  - supply-chain
  - npm
  - shai-hulud
  - credential-theft
summary: "StepSecurity described a Mini Shai-Hulud npm campaign against SAP-related packages where preinstall hooks downloaded Bun, launched an obfuscated payload, scraped runner memory, created public GitHub dead-drop repositories, and attempted developer-workstation persistence."
sourceCount: 1
---

## Executive Summary

StepSecurity described a Mini Shai-Hulud npm campaign against SAP-related packages where preinstall hooks downloaded Bun, launched an obfuscated payload, scraped runner memory, created public GitHub dead-drop repositories, and attempted developer-workstation persistence.

This folder ports older Astro-era supply-chain coverage into the canonical `hp-posts-info` authoring shape so the Next.js/Postgres importer can serve it. The current status is `needs_review`: the source-backed indicators are captured, but the pass intentionally does not claim fresh artifact diffing beyond the cited primary research.

## Key Facts

* **Affected assets:** mbt, @cap-js/sqlite, @cap-js/postgres, @cap-js/db-service.
* **Execution trigger:** npm preinstall hook runs node setup.mjs, downloads Bun, and launches execution.js.
* **Credential risk:** GitHub, OIDC, cloud, package-registry, and developer credentials reachable from impacted CI or developer environments.
* **Relationship:** migrated from the older Astro blog supply-chain roundup into a standalone Next.js/Postgres-ready incident folder.

## Defender Handling

Run the included scope scanner over repository exports, package caches, CI logs, and endpoint telemetry. Treat matches in live dependency manifests, lockfiles, workflow definitions, or runner process/network logs as exposure signals until the owning team confirms whether the malicious artifact actually executed.

## Open Questions

This migration captures coverage and source-backed selectors. Before marking publish-ready, perform fresh artifact diffing, validate current package/action cleanup status, and reconcile exact downstream victim counts from direct maintainer or platform sources.

## Sources

1. [StepSecurity primary research](https://www.stepsecurity.io/blog/a-mini-shai-hulud-has-appeared). **Role:** PRIMARY_RESEARCH **Impact:** Primary source for affected assets, execution trigger, payload behavior, and published IOCs.
