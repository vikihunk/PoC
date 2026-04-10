#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "artifacts" / "kernel" / "payload_manifest.json"
MANIFEST_SIG_PATH = ROOT / "artifacts" / "kernel" / "payload_manifest.sig"
PUBKEY_PEM_PATH = ROOT / "keys" / "root_pub.pem"


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {path}")


def verify_manifest_signature() -> None:
    cmd = [
        "openssl",
        "dgst",
        "-sha256",
        "-verify",
        str(PUBKEY_PEM_PATH),
        "-signature",
        str(MANIFEST_SIG_PATH),
        str(MANIFEST_PATH),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "u-boot rejected boot: payload manifest signature verification failed\n"
            f"{result.stderr.strip()}"
        )


def verify_payload_hashes() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for payload in manifest["payloads"]:
        payload_path = ROOT / Path(payload["path"])
        require_file(payload_path)
        actual_hash = hashlib.sha256(payload_path.read_bytes()).hexdigest()
        expected_hash = payload["sha256"].lower()
        if actual_hash != expected_hash:
            raise RuntimeError(
                "u-boot rejected boot: payload hash mismatch for "
                f"{payload['name']} ({payload_path})"
            )


def main() -> int:
    try:
        for path in (MANIFEST_PATH, MANIFEST_SIG_PATH, PUBKEY_PEM_PATH):
            require_file(path)
        verify_manifest_signature()
        verify_payload_hashes()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print("u-boot verification passed: signed manifest and kernel payload hashes are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
