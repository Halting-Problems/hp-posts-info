#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "@immobiliarelabs/backstage-plugin-gitlab",
    "@immobiliarelabs/backstage-plugin-gitlab-backend",
    "@immobiliarelabs/backstage-plugin-ldap-auth",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend"
]
PACKAGE_VERSIONS = [
    "@immobiliarelabs/backstage-plugin-gitlab@1.0.1",
    "@immobiliarelabs/backstage-plugin-gitlab@2.1.2",
    "@immobiliarelabs/backstage-plugin-gitlab@3.0.3",
    "@immobiliarelabs/backstage-plugin-gitlab@4.0.2",
    "@immobiliarelabs/backstage-plugin-gitlab@5.2.1",
    "@immobiliarelabs/backstage-plugin-gitlab@6.13.1",
    "@immobiliarelabs/backstage-plugin-gitlab@7.0.2",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@3.0.3",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@4.0.2",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@5.2.1",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@6.13.1",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@7.0.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth@1.1.4",
    "@immobiliarelabs/backstage-plugin-ldap-auth@2.0.5",
    "@immobiliarelabs/backstage-plugin-ldap-auth@3.0.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth@4.3.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth@5.2.1",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@1.1.3",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@2.0.5",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@3.0.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@4.3.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@5.2.1"
]
FILES = [
    "binding.gyp",
    "index.js",
    "package/binding.gyp",
    "package/index.js"
]
HASHES = [
    "d830d5b00af9bfe60347dbda5e93d924aac37a39",
    "7ae466337c9f0951feae7b30d6f4b8afc8066bf8",
    "7b4d99626d9c8bfa9fa0f8006e6d37c66320e57d",
    "92a67fe894bdcbb563cf8e09309e41ca34d4773a",
    "a36134e065b6317977cefdd689e4f618634d4919",
    "5987abaf99305c4d9be48ebf35f255cd37b2dbc6",
    "6bd93e1adce382d2172e68ad9fcb73b7e2281de8",
    "6c0196d7df24c4f8c5fa67e179b3864cee571437",
    "5e4fb65fe26b1d81eed844a071218b8e80cb05cc",
    "4ae5348a58060816646ae681495dff6b51ac8a3e",
    "a28eb85ec7d79c7dbb4200e3b79043b2e001a77a",
    "ce5c35e2d682a30a54b64f954c50fa5297f24908",
    "0ef092f8a08f98cdb9670496e2bbe567dde514e0",
    "c63e6d86ebe37f171040f18d916eab0b943e1c26",
    "5b03aec413b8cdb5816ceefe01b6d5d567ea1265",
    "08664303657e7889f51f4d1fe4882847873d165c",
    "de475c8e984307e741f3fa806e8576dc6ae4e3f8",
    "babfa31e6b21e88bd04bd83a066e364d40eb9180",
    "9c70373f80c11afed6cac96363044573a4674f08",
    "4bfc39e5187c2337d76a6999fa085e4332e7ae8b",
    "061a099c939e418bf09b5796852590f0e8ac7e42",
    "54ef1bbcbbcdf9390c70b4628934b434ea871174",
    "7a879ed69a8191df5c68535f6ac41b830577b698de943c66ff40e51482d90d79"
]
PROCESS_PATTERNS = [
    "node-gyp rebuild",
    "node index.js",
    "binding.gyp"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
    'process_patterns': PROCESS_PATTERNS
}

def main() -> int:
    try:
        runtime_path = Path(__file__).resolve().parents[2] / "scanner_runtime.py"
        spec = importlib.util.spec_from_file_location("hp_scanner_runtime", runtime_path)
        if spec is None or spec.loader is None:
            print(f"scanner runtime not found: {runtime_path}", file=sys.stderr)
            return 2
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        args = list(sys.argv[1:])
        if os.environ.get("LOG_ROOT") and "--log-root" not in args:
            args.extend(["--log-root", os.environ["LOG_ROOT"]])
        if os.environ.get("OUT") and "--out" not in args:
            args.extend(["--out", os.environ["OUT"]])
        return runtime.main(args, PROFILE) if args else 2
    except Exception as exc:
        print(f"scanner execution error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
