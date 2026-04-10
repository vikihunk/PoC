#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
KEY_PATH = ROOT / "keys" / "root_pub.der"
EFUSE_HASH_PATH = ROOT / "efuse" / "root_pubkey.sha256"
UBOOT_PATH = ROOT / "artifacts" / "u-boot.bin"
UBOOT_SIG_PATH = ROOT / "artifacts" / "u-boot.bin.sig"
PUBKEY_PEM_PATH = ROOT / "keys" / "root_pub.pem"


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {path}")


def verify_pubkey_hash() -> None:
    expected_hash = EFUSE_HASH_PATH.read_text(encoding="utf-8").strip().lower()
    actual_hash = hashlib.sha256(KEY_PATH.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise RuntimeError(
            "stage0 rejected boot: root public key hash does not match simulated eFuse"
        )


def verify_signature() -> None:
    cmd = [
        "openssl",
        "dgst",
        "-sha256",
        "-verify",
        str(PUBKEY_PEM_PATH),
        "-signature",
        str(UBOOT_SIG_PATH),
        str(UBOOT_PATH),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "stage0 rejected boot: u-boot signature verification failed\n"
            f"{result.stderr.strip()}"
        )


def main() -> int:
    try:
        for path in (KEY_PATH, EFUSE_HASH_PATH, UBOOT_PATH, UBOOT_SIG_PATH, PUBKEY_PEM_PATH):
            require_file(path)
        verify_pubkey_hash()
        verify_signature()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print("stage0 verification passed: simulated eFuse authenticated root key and u-boot.bin")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
