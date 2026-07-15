#!/usr/bin/env python3
"""Extract table cells from the locally saved JFrog Lucide Proxy article.

This parser never executes page code. It reads static HTML and emits only the
two structured tables needed for evidence review.
"""

from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tables: list[list[list[str]]] = []
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in {"th", "td"} and self._row is not None:
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"th", "td"} and self._cell is not None and self._row is not None:
            value = html.unescape("".join(self._cell))
            self._row.append(re.sub(r"\s+", " ", value).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            if self._row:
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None


def main() -> None:
    parser = TableParser()
    parser.feed((ROOT / "jfrog-lucide-proxy.html").read_text(encoding="utf-8"))

    package_table = next(table for table in parser.tables if table and table[0] == ["Package Name", "Malicious Versions", "Xray ID"])
    packages = [
        {
            "ecosystem": "npm",
            "name": row[0],
            "malicious_versions": [value.strip() for value in row[1].split(",")],
            "xray_id": row[2],
        }
        for row in package_table[1:]
    ]

    timeline_table = next(table for table in parser.tables if table and table[0][:2] == ["Date", "Event"])
    timeline = [
        {"date": row[0], "event": row[1], "phase": row[2] if len(row) > 2 else ""}
        for row in timeline_table[1:]
    ]

    (ROOT / "jfrog-package-version-table.json").write_text(
        json.dumps(packages, indent=2) + "\n", encoding="utf-8"
    )
    (ROOT / "jfrog-timeline-table.json").write_text(
        json.dumps(timeline, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"table_count": len(parser.tables), "package_rows": len(packages), "timeline_rows": len(timeline)}))


if __name__ == "__main__":
    main()
