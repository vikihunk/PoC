# Secure Boot PoC

This proof of concept models a simple verified boot chain in software:

1. A root ECC keypair is generated.
2. The SHA-256 hash of the root public key is written to a simulated eFuse.
3. Stage 0 reads the eFuse hash, authenticates the root public key, and verifies a signed `u-boot.bin`.
4. U-Boot verifies a signed Linux payload manifest and then checks the hashes of the kernel payloads listed in that manifest.

This is a software model, not a hardware-backed secure boot implementation. It is intended to validate the flow and trust boundaries before moving to real bootloader code.

See [SECURE_BOOT_POC.md](/home/bikumar/workspace/PoC/secure_boot_poc/SECURE_BOOT_POC.md) for the design and trust model.

## Layout

- `keys/`: generated ECC key material
- `efuse/`: simulated read-only eFuse contents
- `artifacts/`: generated U-Boot and Linux payload artifacts
- `scripts/`: generation and verification scripts

## Quick Start

Run the full demo:

```bash
cd /home/bikumar/workspace/PoC/secure_boot_poc
make demo
```

Run the checks separately:

```bash
make prepare
make verify-stage0
make verify-uboot
```

Clean generated output:

```bash
make clean
```

## Requirements

- `python3`
- `openssl`
