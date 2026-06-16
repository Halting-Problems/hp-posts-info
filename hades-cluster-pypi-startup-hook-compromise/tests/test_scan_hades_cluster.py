from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_scan_hades_cluster_detects_package_and_hook_markers(tmp_path: Path) -> None:
  root = tmp_path / "scope"
  (root / "site-packages").mkdir(parents=True)
  (root / "site-packages" / "_index.js").write_text("mflux-streamlit\nmrbios\n", encoding="utf-8")
  (root / "site-packages" / "mflux-streamlit-0.0.4.dist-info").mkdir()
  (root / "site-packages" / "mflux-streamlit-0.0.4.dist-info" / "top_level.txt").write_text(
    "mflux-streamlit\n",
    encoding="utf-8",
  )
  (root / "logs").mkdir()
  (root / "logs" / "registry.log").write_text("pypi:project-status=quarantined\n", encoding="utf-8")
  (root / "hooks").mkdir()
  (root / "hooks" / "*-setup.pth").write_text("import _index\n", encoding="utf-8")

  script = Path(__file__).resolve().parents[1] / "scripts" / "scan_hades_cluster.py"
  out = tmp_path / "out"
  proc = subprocess.run(
    [sys.executable, str(script), str(root), "--out", str(out)],
    check=True,
    capture_output=True,
    text=True,
  )
  data = json.loads(proc.stdout)
  assert data["package_hits"]
  assert data["file_hits"]
  assert data["registry_hits"]
  assert (out / "scan-summary.json").exists()
