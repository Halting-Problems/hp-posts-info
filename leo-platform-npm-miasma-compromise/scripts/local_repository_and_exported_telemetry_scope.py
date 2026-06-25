#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
LOG_ROOT = Path(os.environ['LOG_ROOT']).resolve() if os.environ.get('LOG_ROOT') else None
OUT = Path(os.environ.get('OUT', 'hp-leo-platform-npm-miasma-compromise-scope'))
OUT.mkdir(parents=True, exist_ok=True)
INDICATORS_FILE = OUT / 'indicators.txt'

PACKAGES = [
    'hexo-deployer-wrangler',
    'hexo-shoka-swiper',
    'leo-auth',
    'leo-aws',
    'leo-cache',
    'leo-cdk-lib',
    'leo-cli',
    'leo-config',
    'leo-connector-elasticsearch',
    'leo-connector-mongo',
    'leo-connector-mysql',
    'leo-connector-oracle',
    'leo-connector-redshift',
    'leo-cron',
    'leo-logger',
    'leo-sdk',
    'leo-streams',
    'prism-silq',
    'rstreams-metrics',
    'rstreams-shard-util',
    'serverless-convention',
    'serverless-leo',
    'solo-nav',
]
PACKAGE_VERSIONS = [
    'leo-logger@1.0.8',
    'leo-sdk@6.0.19',
    'leo-aws@2.0.4',
    'leo-config@1.1.1',
    'leo-streams@2.0.1',
    'serverless-leo@3.0.14',
    'leo-connector-mongo@3.0.8',
    'serverless-convention@2.0.4',
    'rstreams-metrics@2.0.2',
    'leo-connector-elasticsearch@2.0.6',
    'leo-auth@4.0.6',
    'leo-cache@1.0.2',
    'leo-cli@3.0.3',
    'hexo-deployer-wrangler@1.0.4',
    'hexo-shoka-swiper@0.1.10',
    'leo-cron@2.0.2',
    'leo-connector-redshift@3.0.6',
    'leo-connector-oracle@2.0.1',
    'prism-silq@1.0.1',
    'rstreams-shard-util@1.0.1',
    'leo-connector-mysql@3.0.3',
    'leo-cdk-lib@0.0.2',
    'solo-nav@1.0.1',
]
FILES = [
    'binding.gyp',
    'index.js',
    'stub.c',
]
HASHES = [
    'd45ad3cffbcc7c4b354ebe9d71d002fa585379ec',
    '1dcc0a39e1cd7293a9058cfc41e1afe8b397c943',
    'ef8bf6dd92cbc29ef8d23f3f0fa786ed20a856b1',
    '9be49287057cd6a54ef4a70a8d541a7259efbd2d',
    'c05068f18e7f94304b92a307a030e0038ab61004',
    'cb78d0dca573f99a22b41ca01e99853a6162d5d5',
    'c721c184dbb5c2dc23bacfd28571daef1decfac1',
]
DOMAINS = [
    'api.github.com',
    'github.com',
]
URLS = [
    'https://api.github.com/graphql',
    'https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/',
]
PROCESS_PATTERNS = [
    'Runner.Worker',
    '/proc/{pid}/mem',
    'bypass_2fa',
    'ALL=(ALL) NOPASSWD:ALL',
    '/tmp/p',
]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='ignore')
    except Exception as exc:
        return f'__READ_ERROR__:{path}:{exc}'


def scan_tree(base: Path, indicators: set[str]) -> list[str]:
    matches: list[str] = []
    exclude_dirs = {'.git', 'node_modules', 'vendor', 'dist', '.venv'}
    for root, dirs, filenames in os.walk(base):
        dirs[:] = [directory for directory in dirs if directory not in exclude_dirs]
        for filename in filenames:
            file_path = Path(root) / filename
            content = read_text(file_path)
            if content.startswith('__READ_ERROR__'):
                matches.append(content)
                continue
            for indicator in indicators:
                if indicator in content:
                    matches.append(f"{file_path}: found '{indicator}'")
    return matches


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')


indicators = set()
for group in [PACKAGES, PACKAGE_VERSIONS, FILES, HASHES, DOMAINS, URLS, PROCESS_PATTERNS]:
    for value in group:
        indicators.add(value)

write_lines(INDICATORS_FILE, sorted(indicators))
print(f'[+] Wrote {len(indicators)} selectors to {INDICATORS_FILE}')

repository_matches = scan_tree(ROOT, indicators)
if repository_matches:
    repository_path = OUT / 'repository-indicator-matches.txt'
    write_lines(repository_path, repository_matches)
    print(f'[!] Found {len(repository_matches)} repository matches -> {repository_path}')
else:
    print('[+] No repository matches found in target root.')

if LOG_ROOT and LOG_ROOT.exists():
    telemetry_matches = scan_tree(LOG_ROOT, indicators)
    if telemetry_matches:
        telemetry_path = OUT / 'exported-telemetry-indicator-matches.txt'
        write_lines(telemetry_path, telemetry_matches)
        print(f'[!] Found {len(telemetry_matches)} telemetry matches -> {telemetry_path}')
    else:
        print('[+] No telemetry matches found in LOG_ROOT.')

registry_dir = OUT / 'registry'
registry_dir.mkdir(exist_ok=True)
for package in PACKAGES:
    response = subprocess.run(
        ['npm', 'view', package, 'name', 'time', 'dist-tags', 'versions', '--json'],
        capture_output=True,
        text=True,
        check=False,
    )
    output_path = registry_dir / f"npm-{package.replace('/', '__')}.json"
    if response.returncode == 0:
        output_path.write_text(response.stdout, encoding='utf-8')
    else:
        output_path.write_text(response.stdout + '\n' + response.stderr, encoding='utf-8')

print(f'[+] Wrote scope artifacts under {OUT}')
