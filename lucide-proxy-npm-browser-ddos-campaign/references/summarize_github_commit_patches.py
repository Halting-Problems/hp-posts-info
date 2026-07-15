#!/usr/bin/env python3
"""Summarize saved GitHub commit patches without emitting untrusted code."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TOKENS = {
    "remote_loader_reference": "cdn.jsdelivr.net",
    "websocket_constructor": "WebSocket",
    "wisp_reference": "wisp",
    "beacon_reference": "sendBeacon",
    "local_storage_reference": "localStorage",
    "cookie_reference": "cookie",
    "loopback_target": "localhost",
}


def main() -> None:
    results = []
    for path in sorted(ROOT.glob("github-commit-*.json")):
        if path.name == "github-commit-index.json":
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        patch_text = "\n".join(
            str(file.get("patch", ""))
            for file in document.get("files", [])
            if isinstance(file, dict)
        )
        results.append(
            {
                "sha": document.get("sha"),
                "html_url": document.get("html_url"),
                "commit_date": document.get("commit", {}).get("committer", {}).get("date"),
                "changed_files": document.get("files", []).__len__(),
                "patch_truncated_files": sum(
                    1 for file in document.get("files", []) if "patch" not in file
                ),
                "token_counts_in_returned_patches": {
                    label: patch_text.lower().count(token.lower())
                    for label, token in TOKENS.items()
                },
                "note": "Zero is not evidence of absence when GitHub omitted or truncated patches.",
            }
        )
    (ROOT / "github-commit-static-summary.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"commits_summarized": len(results)}))


if __name__ == "__main__":
    main()
