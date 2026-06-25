import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / 'scripts' / 'local_repository_and_exported_telemetry_scope.py'


def run_script(scan_dir: Path, out_dir: Path, log_dir: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(**__import__('os').environ)
    env['OUT'] = str(out_dir)
    if log_dir is not None:
        env['LOG_ROOT'] = str(log_dir)
    else:
        env.pop('LOG_ROOT', None)
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(scan_dir)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_script_runs_clean_directory(tmp_path: Path):
    scan_dir = tmp_path / 'scan'
    out_dir = tmp_path / 'out'
    scan_dir.mkdir()
    out_dir.mkdir()

    result = run_script(scan_dir, out_dir)

    assert result.returncode == 0
    assert (out_dir / 'indicators.txt').exists()
    assert not (out_dir / 'repository-indicator-matches.txt').exists()


def test_script_detects_package_and_behavioral_indicator(tmp_path: Path):
    scan_dir = tmp_path / 'scan'
    out_dir = tmp_path / 'out'
    scan_dir.mkdir()
    out_dir.mkdir()
    hit_file = scan_dir / 'package-lock.json'
    hit_file.write_text(
        'leo-sdk@6.0.19\nRunner.Worker\nhttps://api.github.com/graphql\n',
        encoding='utf-8',
    )

    result = run_script(scan_dir, out_dir)

    assert result.returncode == 0
    matches = (out_dir / 'repository-indicator-matches.txt').read_text(encoding='utf-8')
    assert 'leo-sdk@6.0.19' in matches
    assert 'Runner.Worker' in matches
    assert 'https://api.github.com/graphql' in matches


def test_script_detects_log_root_hits(tmp_path: Path):
    scan_dir = tmp_path / 'scan'
    log_dir = tmp_path / 'logs'
    out_dir = tmp_path / 'out'
    scan_dir.mkdir()
    log_dir.mkdir()
    out_dir.mkdir()
    (log_dir / 'gha.log').write_text('/proc/{pid}/mem\nALL=(ALL) NOPASSWD:ALL\n', encoding='utf-8')

    result = run_script(scan_dir, out_dir, log_dir)

    assert result.returncode == 0
    telemetry_matches = (out_dir / 'exported-telemetry-indicator-matches.txt').read_text(encoding='utf-8')
    assert '/proc/{pid}/mem' in telemetry_matches
    assert 'ALL=(ALL) NOPASSWD:ALL' in telemetry_matches
