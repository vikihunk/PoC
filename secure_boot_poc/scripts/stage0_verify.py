#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUNTIME_STAGE0_DIR = ROOT / "runtime" / "stage0"
KEY_PATH = ROOT / "keys" / "root_pub.der"
EFUSE_HASH_PATH = ROOT / "efuse" / "root_pubkey.sha256"
UBOOT_PATH = ROOT / "artifacts" / "u-boot.bin"
UBOOT_SIG_PATH = ROOT / "artifacts" / "u-boot.bin.sig"
PUBKEY_PEM_PATH = ROOT / "keys" / "root_pub.pem"
VERIFIED_UBOOT_PATH = RUNTIME_STAGE0_DIR / "u-boot.verified.bin"
HANDOFF_PATH = RUNTIME_STAGE0_DIR / "handoff.json"


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {path}")


def verify_pubkey_hash(pubkey_der: bytes, expected_hash: str) -> None:
    actual_hash = hashlib.sha256(pubkey_der).hexdigest()
    if actual_hash != expected_hash:
        raise RuntimeError(
            "stage0 rejected boot: root public key hash does not match simulated eFuse"
        )


def read_boot_inputs() -> tuple[bytes, str, bytes, bytes, bytes]:
    pubkey_der = KEY_PATH.read_bytes()
    expected_hash = EFUSE_HASH_PATH.read_text(encoding="utf-8").strip().lower()
    uboot_bytes = UBOOT_PATH.read_bytes()
    uboot_sig = UBOOT_SIG_PATH.read_bytes()
    pubkey_pem = PUBKEY_PEM_PATH.read_bytes()
    return pubkey_der, expected_hash, uboot_bytes, uboot_sig, pubkey_pem


def verify_signature(pubkey_pem: bytes, signature: bytes, payload: bytes) -> None:
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        pubkey_path = temp_dir / "root_pub.pem"
        sig_path = temp_dir / "u-boot.bin.sig"
        payload_path = temp_dir / "u-boot.bin"
        pubkey_path.write_bytes(pubkey_pem)
        sig_path.write_bytes(signature)
        payload_path.write_bytes(payload)

        cmd = [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(pubkey_path),
            "-signature",
            str(sig_path),
            str(payload_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(
                "stage0 rejected boot: u-boot signature verification failed\n"
                f"{result.stderr.strip()}"
            )


def persist_verified_handoff(uboot_bytes: bytes) -> None:
    RUNTIME_STAGE0_DIR.mkdir(parents=True, exist_ok=True)
    VERIFIED_UBOOT_PATH.write_bytes(uboot_bytes)
    handoff = {
        "source_path": str(UBOOT_PATH.relative_to(ROOT)),
        "verified_path": str(VERIFIED_UBOOT_PATH.relative_to(ROOT)),
        "sha256": hashlib.sha256(uboot_bytes).hexdigest(),
    }
    HANDOFF_PATH.write_text(json.dumps(handoff, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    try:
        for path in (KEY_PATH, EFUSE_HASH_PATH, UBOOT_PATH, UBOOT_SIG_PATH, PUBKEY_PEM_PATH):
            require_file(path)
        pubkey_der, expected_hash, uboot_bytes, uboot_sig, pubkey_pem = read_boot_inputs()
        verify_pubkey_hash(pubkey_der, expected_hash)
        verify_signature(pubkey_pem, uboot_sig, uboot_bytes)
        persist_verified_handoff(uboot_bytes)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "stage0 verification passed: simulated eFuse authenticated root key and "
        "runtime/stage0/u-boot.verified.bin is the verified handoff"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
