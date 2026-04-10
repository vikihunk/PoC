#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="${ROOT_DIR}/keys"
EFUSE_DIR="${ROOT_DIR}/efuse"
ARTIFACT_DIR="${ROOT_DIR}/artifacts"
KERNEL_DIR="${ARTIFACT_DIR}/kernel"

mkdir -p "${KEY_DIR}" "${EFUSE_DIR}" "${ARTIFACT_DIR}" "${KERNEL_DIR}"

openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out "${KEY_DIR}/root_priv.pem"
openssl pkey -in "${KEY_DIR}/root_priv.pem" -pubout -out "${KEY_DIR}/root_pub.pem"
openssl pkey -pubin -in "${KEY_DIR}/root_pub.pem" -outform DER -out "${KEY_DIR}/root_pub.der"
openssl dgst -sha256 -binary "${KEY_DIR}/root_pub.der" | xxd -p -c 256 > "${EFUSE_DIR}/root_pubkey.sha256"

cat > "${ARTIFACT_DIR}/u-boot.bin" <<'EOF'
SIMULATED U-BOOT
build-id=secure-boot-poc
board=qemu-virt
purpose=stage1-verification
EOF

cat > "${KERNEL_DIR}/Image" <<'EOF'
SIMULATED LINUX KERNEL IMAGE
version=6.12-poc
cmdline=console=ttyAMA0 root=/dev/vda
EOF

cat > "${KERNEL_DIR}/board.dtb" <<'EOF'
SIMULATED DEVICETREE
model=qemu-virt-poc
EOF

cat > "${KERNEL_DIR}/initramfs.cpio" <<'EOF'
SIMULATED INITRAMFS
contains=/init
EOF

openssl dgst -sha256 -sign "${KEY_DIR}/root_priv.pem" \
  -out "${ARTIFACT_DIR}/u-boot.bin.sig" \
  "${ARTIFACT_DIR}/u-boot.bin"

KERNEL_HASH="$(openssl dgst -sha256 -r "${KERNEL_DIR}/Image" | awk '{print $1}')"
DTB_HASH="$(openssl dgst -sha256 -r "${KERNEL_DIR}/board.dtb" | awk '{print $1}')"
INITRAMFS_HASH="$(openssl dgst -sha256 -r "${KERNEL_DIR}/initramfs.cpio" | awk '{print $1}')"

cat > "${KERNEL_DIR}/payload_manifest.json" <<EOF
{
  "algorithm": "sha256",
  "payloads": [
    {
      "name": "Image",
      "path": "artifacts/kernel/Image",
      "sha256": "${KERNEL_HASH}"
    },
    {
      "name": "board.dtb",
      "path": "artifacts/kernel/board.dtb",
      "sha256": "${DTB_HASH}"
    },
    {
      "name": "initramfs.cpio",
      "path": "artifacts/kernel/initramfs.cpio",
      "sha256": "${INITRAMFS_HASH}"
    }
  ]
}
EOF

openssl dgst -sha256 -sign "${KEY_DIR}/root_priv.pem" \
  -out "${KERNEL_DIR}/payload_manifest.sig" \
  "${KERNEL_DIR}/payload_manifest.json"

printf 'Prepared secure boot demo artifacts in %s\n' "${ROOT_DIR}"
