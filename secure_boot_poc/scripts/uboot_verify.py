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
RUNTIME_UBOOT_DIR = ROOT / "runtime" / "uboot"
MANIFEST_PATH = ROOT / "artifacts" / "kernel" / "payload_manifest.json"
MANIFEST_SIG_PATH = ROOT / "artifacts" / "kernel" / "payload_manifest.sig"
PUBKEY_PEM_PATH = ROOT / "keys" / "root_pub.pem"
STAGE0_HANDOFF_PATH = RUNTIME_STAGE0_DIR / "handoff.json"
STAGE0_VERIFIED_UBOOT_PATH = RUNTIME_STAGE0_DIR / "u-boot.verified.bin"
UBOOT_HANDOFF_PATH = RUNTIME_UBOOT_DIR / "payloads.json"


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {path}")


def read_boot_inputs() -> tuple[dict, bytes, bytes, bytes]:
    manifest_bytes = MANIFEST_PATH.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    manifest_sig = MANIFEST_SIG_PATH.read_bytes()
    pubkey_pem = PUBKEY_PEM_PATH.read_bytes()
    return manifest, manifest_bytes, manifest_sig, pubkey_pem


def verify_stage0_handoff() -> None:
    handoff = json.loads(STAGE0_HANDOFF_PATH.read_text(encoding="utf-8"))
    verified_uboot = STAGE0_VERIFIED_UBOOT_PATH.read_bytes()
    actual_hash = hashlib.sha256(verified_uboot).hexdigest()
    expected_hash = handoff["sha256"].lower()
    if actual_hash != expected_hash:
        raise RuntimeError("u-boot rejected boot: stage0 verified handoff was modified")


def verify_manifest_signature(pubkey_pem: bytes, signature: bytes, manifest_bytes: bytes) -> None:
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        pubkey_path = temp_dir / "root_pub.pem"
        sig_path = temp_dir / "payload_manifest.sig"
        manifest_path = temp_dir / "payload_manifest.json"
        pubkey_path.write_bytes(pubkey_pem)
        sig_path.write_bytes(signature)
        manifest_path.write_bytes(manifest_bytes)

        cmd = [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(pubkey_path),
            "-signature",
            str(sig_path),
            str(manifest_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(
                "u-boot rejected boot: payload manifest signature verification failed\n"
                f"{result.stderr.strip()}"
            )


def verify_payload_hashes(manifest: dict) -> list[dict[str, str]]:
    verified_payloads: list[dict[str, str]] = []
    for payload in manifest["payloads"]:
        payload_path = ROOT / Path(payload["path"])
        require_file(payload_path)
        payload_bytes = payload_path.read_bytes()
        actual_hash = hashlib.sha256(payload_bytes).hexdigest()
        expected_hash = payload["sha256"].lower()
        if actual_hash != expected_hash:
            raise RuntimeError(
                "u-boot rejected boot: payload hash mismatch for "
                f"{payload['name']} ({payload_path})"
            )
        verified_path = RUNTIME_UBOOT_DIR / payload["name"]
        verified_path.write_bytes(payload_bytes)
        verified_payloads.append(
            {
                "name": payload["name"],
                "source_path": payload["path"],
                "verified_path": str(verified_path.relative_to(ROOT)),
                "sha256": actual_hash,
            }
        )
    return verified_payloads


def persist_verified_handoff(verified_payloads: list[dict[str, str]]) -> None:
    RUNTIME_UBOOT_DIR.mkdir(parents=True, exist_ok=True)
    UBOOT_HANDOFF_PATH.write_text(
        json.dumps({"payloads": verified_payloads}, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    try:
        for path in (
            MANIFEST_PATH,
            MANIFEST_SIG_PATH,
            PUBKEY_PEM_PATH,
            STAGE0_HANDOFF_PATH,
            STAGE0_VERIFIED_UBOOT_PATH,
        ):
            require_file(path)
        verify_stage0_handoff()
        manifest, manifest_bytes, manifest_sig, pubkey_pem = read_boot_inputs()
        verify_manifest_signature(pubkey_pem, manifest_sig, manifest_bytes)
        RUNTIME_UBOOT_DIR.mkdir(parents=True, exist_ok=True)
        verified_payloads = verify_payload_hashes(manifest)
        persist_verified_handoff(verified_payloads)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        "u-boot verification passed: signed manifest and payload buffers were copied to "
        "runtime/uboot/ as the verified handoff"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
