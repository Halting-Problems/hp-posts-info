---
title: "Miasma Worm Hits Microsoft Azure Repositories"
date: 2026-06-05
severity: "critical"
tags:
  - supply-chain
  - github
  - miasma
  - developer-tooling
summary: "StepSecurity reported that the Miasma worm reached Microsoft Azure GitHub organizations after a compromised contributor account pushed malicious workspace and AI-assistant hook files into Azure/durabletask, prompting GitHub to disable 73 repositories across four Microsoft organizations."
sourceCount: 1
---

## Executive Summary

StepSecurity reported that the Miasma worm reached Microsoft Azure GitHub organizations after a compromised contributor account pushed malicious workspace and AI-assistant hook files into Azure/durabletask, prompting GitHub to disable 73 repositories across four Microsoft organizations.

This folder ports older Astro-era supply-chain coverage into the canonical `hp-posts-info` authoring shape so the Next.js/Postgres importer can serve it. The current status is `needs_review`: the source-backed indicators are captured, but the pass intentionally does not claim fresh artifact diffing beyond the cited primary research.

## Key Facts

* **Affected assets:** Azure/durabletask, Azure/azure-functions-action.
* **Execution trigger:** developer or automation opens/uses a repository containing planted IDE and AI-assistant hook files.
* **Credential risk:** GitHub, OIDC, cloud, package-registry, and developer credentials reachable from impacted CI or developer environments.
* **Relationship:** migrated from the older Astro blog supply-chain roundup into a standalone Next.js/Postgres-ready incident folder.

## Defender Handling

Run the included scope scanner over repository exports, package caches, CI logs, and endpoint telemetry. Treat matches in live dependency manifests, lockfiles, workflow definitions, or runner process/network logs as exposure signals until the owning team confirms whether the malicious artifact actually executed.

## Open Questions

This migration captures coverage and source-backed selectors. Before marking publish-ready, perform fresh artifact diffing, validate current package/action cleanup status, and reconcile exact downstream victim counts from direct maintainer or platform sources.

## Sources

1. [StepSecurity primary research](https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents). **Role:** PRIMARY_RESEARCH **Impact:** Primary source for affected assets, execution trigger, payload behavior, and published IOCs.
