import os
import sys
import subprocess
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
DETECT_EBPF_MAPS_PY = SCRIPTS_DIR / "detect_ebpf_maps.py"
CHECK_PACKAGE_CACHES_PY = SCRIPTS_DIR / "check_package_caches.py"
CHECK_SYSTEMD_PERSISTENCE_PY = SCRIPTS_DIR / "check_systemd_persistence.py"

def test_detect_ebpf_maps(tmp_path):
    # 1. Test clean state (directory does not exist or is empty)
    bpf_dir = tmp_path / "bpf"
    res = subprocess.run([sys.executable, str(DETECT_EBPF_MAPS_PY), "--bpf-dir", str(bpf_dir)], capture_output=True)
    assert res.returncode == 0

    # 2. Test clean state with existing empty directory
    bpf_dir.mkdir()
    res = subprocess.run([sys.executable, str(DETECT_EBPF_MAPS_PY), "--bpf-dir", str(bpf_dir)], capture_output=True)
    assert res.returncode == 0

    # 3. Test positive state (compromised indicator exists)
    pid_map = bpf_dir / "hidden_pids"
    pid_map.touch()
    res = subprocess.run([sys.executable, str(DETECT_EBPF_MAPS_PY), "--bpf-dir", str(bpf_dir)], capture_output=True)
    assert res.returncode == 1

def test_check_package_caches(tmp_path):
    # 1. Test clean state
    npm_cache = tmp_path / "npm"
    bun_cache = tmp_path / "bun"
    res = subprocess.run([sys.executable, str(CHECK_PACKAGE_CACHES_PY), "--npm-cache", str(npm_cache), "--bun-cache", str(bun_cache)], capture_output=True)
    assert res.returncode == 0

    # 2. Test positive state (NPM cache match)
    npm_cache.mkdir()
    cache_file = npm_cache / "some-cache-entry"
    cache_file.write_text("package atomic-lockfile version 1.4.2")
    res = subprocess.run([sys.executable, str(CHECK_PACKAGE_CACHES_PY), "--npm-cache", str(npm_cache), "--bun-cache", str(bun_cache)], capture_output=True)
    assert res.returncode == 1

def test_check_systemd_persistence(tmp_path):
    # 1. Test clean state
    sysd_dir = tmp_path / "systemd"
    res = subprocess.run([sys.executable, str(CHECK_SYSTEMD_PERSISTENCE_PY), "--systemd-dirs", str(sysd_dir)], capture_output=True)
    assert res.returncode == 0

    # 2. Test positive state
    sysd_dir.mkdir()
    suspicious_service = sysd_dir / "atomic-updater.service"
    suspicious_service.write_text("[Service]\nRestart=always\nRestartSec=30\nExecStart=/usr/bin/deps\n")
    res = subprocess.run([sys.executable, str(CHECK_SYSTEMD_PERSISTENCE_PY), "--systemd-dirs", str(sysd_dir)], capture_output=True)
    assert res.returncode == 1
