# Secure Boot PoC Design

## Goal

Model a boot chain where:

- a root ECC public key is anchored in a simulated eFuse,
- stage 0 verifies `u-boot.bin` before executing it,
- U-Boot verifies the Linux payloads before booting them.

## Trust Model

### Root of Trust

The root of trust is the SHA-256 hash of the ECC public key stored in `efuse/root_pubkey.sha256`.

The eFuse model is intentionally simple:

- it is generated once during provisioning,
- it is treated as read-only input to stage 0,
- it is the only implicitly trusted boot input.

### Stage 0 Responsibilities

Stage 0 does not trust the public key file by itself. It:

1. reads the expected public-key hash from the simulated eFuse,
2. hashes the supplied root public key,
3. rejects the boot if the hash does not match,
4. verifies the signature on `artifacts/u-boot.bin`,
5. transfers control to U-Boot only on success.

This mirrors the real constraint that U-Boot cannot securely verify itself after execution has already started.

### U-Boot Responsibilities

U-Boot is assumed to have been authenticated by stage 0. It then:

1. verifies the signature on `artifacts/kernel/payload_manifest.json`,
2. hashes each payload listed in the manifest,
3. compares the computed hashes with the signed manifest values,
4. rejects boot if any hash or signature check fails.

This approximates a signed FIT image flow without requiring a real U-Boot build in this repository.

## Artifacts

### Keys

- `keys/root_priv.pem`: ECC private key used for signing
- `keys/root_pub.pem`: ECC public key authenticated by stage 0

### Simulated eFuse

- `efuse/root_pubkey.sha256`: SHA-256 of the DER-encoded root public key

### U-Boot Stage

- `artifacts/u-boot.bin`: simulated U-Boot binary
- `artifacts/u-boot.bin.sig`: ECDSA signature for `u-boot.bin`

### Linux Payload Stage

- `artifacts/kernel/Image`: simulated Linux kernel image
- `artifacts/kernel/board.dtb`: simulated device tree
- `artifacts/kernel/initramfs.cpio`: simulated initramfs
- `artifacts/kernel/payload_manifest.json`: signed manifest of payload hashes
- `artifacts/kernel/payload_manifest.sig`: signature for the manifest

## Why The eFuse Stores A Hash

Real hardware commonly anchors either:

- the full public key,
- a hash of the public key,
- a hash of an x509 certificate or key table.

This PoC stores a hash because it matches common ROM behavior and keeps stage 0 simple: authenticate the public key first, then use it for signature verification.

## Command Flow

### Provisioning

`make prepare` performs provisioning and image creation:

1. generate an ECC keypair using `prime256v1`,
2. export the public key in DER form,
3. hash the DER public key into the simulated eFuse file,
4. create simulated U-Boot and Linux payload files,
5. sign `u-boot.bin`,
6. build and sign the Linux payload manifest.

### Verification

`make verify-stage0`:

- authenticates `keys/root_pub.pem` against `efuse/root_pubkey.sha256`,
- verifies `artifacts/u-boot.bin.sig`.

`make verify-uboot`:

- verifies `artifacts/kernel/payload_manifest.sig`,
- verifies the hashes of `Image`, `board.dtb`, and `initramfs.cpio`.

## Limitations

- No real ROM, SPL, TF-A, or U-Boot source is used here.
- No hardware anti-rollback or monotonic versioning is modeled.
- No TPM, TrustZone, or secure storage backend is modeled.
- Signature verification is delegated to `openssl`, not an in-boot crypto library.

## Path To A Real Implementation

To move this toward a real platform flow:

1. replace the stage-0 script with SPL or TF-A verification logic,
2. store the eFuse-backed key hash in platform-specific OTP or ROM configuration,
3. replace the manifest flow with signed FIT verification in U-Boot,
4. add rollback counters and key-rotation policy.
