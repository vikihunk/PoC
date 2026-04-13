# Real VM Build Plan

This document is a manual plan for turning the current software-only secure-boot PoC into a real bootable QEMU ARM64 chain under `/home/bikumar/workspace/PoC`.

The target boot flow is:

1. QEMU `virt` machine
2. Trusted Firmware-A (TF-A) as the early stage
3. U-Boot as BL33
4. Linux kernel on ARM64
5. Stage 0 verification of U-Boot
6. U-Boot verification of Linux payloads

This document is intentionally procedural so you can run the steps later by hand.

## Scope

The current PoC in [secure_boot_poc](/home/bikumar/workspace/PoC/secure_boot_poc) proves the trust logic only. It does not produce bootable artifacts.

This plan upgrades that into a real VM setup by:

- building real TF-A, U-Boot, and Linux sources,
- booting them on QEMU ARM64,
- replacing placeholder payloads with real boot artifacts,
- moving from host-side verification scripts toward boot-stage verification.

## Target Directory Layout

Use this layout under `/home/bikumar/workspace/PoC`:

```text
/home/bikumar/workspace/PoC/
  secure_boot_poc/
  secure_boot_vm/
    src/
      trusted-firmware-a/
      u-boot/
      linux/
    build/
      tf-a/
      u-boot/
      linux/
    images/
    keys/
    efuse/
    scripts/
    docs/
```

Suggested setup:

```bash
cd /home/bikumar/workspace/PoC
mkdir -p secure_boot_vm/{src,build,images,keys,efuse,scripts,docs}
```

## Phase 1: Install Host Dependencies

Install the packages needed for QEMU ARM64, TF-A, U-Boot, and Linux:

```bash
sudo apt update
sudo apt install \
  git make gcc-aarch64-linux-gnu qemu-system-arm \
  device-tree-compiler bison flex swig python3-pyelftools \
  libssl-dev libgnutls28-dev bc libncurses-dev cpio \
  xz-utils rsync
```

Optional but useful:

```bash
sudo apt install gdb-multiarch
```

## Phase 2: Clone Sources

Clone upstream sources into `secure_boot_vm/src`:

```bash
cd /home/bikumar/workspace/PoC/secure_boot_vm/src
git clone https://review.trustedfirmware.org/TF-A/trusted-firmware-a.git
git clone https://source.denx.de/u-boot/u-boot.git
git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
```

If you prefer GitHub mirrors for convenience, you can substitute them, but the above sources are the normal upstreams.

## Phase 3: Generate Signing Material

Reuse the ECC approach from the current PoC, but keep the real VM work separate:

```bash
cd /home/bikumar/workspace/PoC/secure_boot_vm
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out keys/root_priv.pem

openssl pkey -in keys/root_priv.pem -pubout -out keys/root_pub.pem
openssl pkey -pubin -in keys/root_pub.pem -outform DER -out keys/root_pub.der
openssl dgst -sha256 -binary keys/root_pub.der | xxd -p -c 256 > efuse/root_pubkey.sha256
```

This models the root key hash being programmed into eFuse.

## Phase 4: Build a Baseline Bootable Stack First

Do not start with verification enabled. First produce a known-good boot flow:

- TF-A boots on `qemu-system-aarch64`
- TF-A hands off to U-Boot
- U-Boot boots a Linux kernel

This baseline is critical. If boot fails before verification is added, debugging becomes much harder.

### 4.1 Build U-Boot for QEMU ARM64

```bash
cd /home/bikumar/workspace/PoC/secure_boot_vm/src/u-boot
make distclean
make qemu_arm64_defconfig CROSS_COMPILE=aarch64-linux-gnu-
make -j$(nproc) CROSS_COMPILE=aarch64-linux-gnu-
```

Expected useful outputs:

- `u-boot.bin`
- `u-boot-nodtb.bin`
- `u-boot.dtb`
- `u-boot.elf`

### 4.2 Build TF-A for QEMU `virt`

Use U-Boot as BL33:

```bash
cd /home/bikumar/workspace/PoC/secure_boot_vm/src/trusted-firmware-a
make distclean
make PLAT=qemu ARCH=aarch64 DEBUG=1 \
  CROSS_COMPILE=aarch64-linux-gnu- \
  BL33=/home/bikumar/workspace/PoC/secure_boot_vm/src/u-boot/u-boot.bin \
  all fip
```

Expected outputs are typically under:

- `build/qemu/debug/bl1.bin`
- `build/qemu/debug/fip.bin`

The exact paths depend on TF-A revision.

### 4.3 Build Linux for ARM64 QEMU

```bash
cd /home/bikumar/workspace/PoC/secure_boot_vm/src/linux
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
make -j$(nproc) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image
```

Expected output:

- `arch/arm64/boot/Image`

For the QEMU `virt` machine, Linux may use a DTB supplied by QEMU or one passed separately. Start simple and let U-Boot/QEMU handle DTB provision if possible.

## Phase 5: Boot The Baseline VM

Start with a direct test that proves TF-A, U-Boot, and Linux all work together before adding verification.

Example baseline QEMU command:

```bash
qemu-system-aarch64 \
  -machine virt,secure=on \
  -cpu cortex-a57 \
  -smp 2 \
  -m 2048 \
  -nographic \
  -bios /home/bikumar/workspace/PoC/secure_boot_vm/src/trusted-firmware-a/build/qemu/debug/bl1.bin \
  -device loader,file=/home/bikumar/workspace/PoC/secure_boot_vm/src/trusted-firmware-a/build/qemu/debug/fip.bin,addr=0x04000000,force-raw=on
```

You will likely need to adapt this command to the exact TF-A QEMU documentation for the revision you cloned. The key goal in this phase is not elegance; it is proving the chain boots.

Success criteria:

- TF-A banner appears
- U-Boot starts
- You reach the U-Boot shell

At this point, boot Linux manually from the U-Boot shell first.

## Phase 6: Boot Linux From U-Boot

There are two reasonable ways to continue:

### Option A: Start With Loose Files

Load the kernel into memory and boot manually from the U-Boot prompt. This is easier for bring-up.

### Option B: Move Directly To A FIT Image

Create a FIT image that contains:

- kernel
- DTB
- optional initramfs
- signature metadata

For your final goal, FIT is the better path because U-Boot already has verified-boot support around FIT images.

Recommended approach:

1. bring up Linux using the simplest possible manual boot path,
2. once stable, switch to a signed FIT image.

## Device Tree Plan

The device tree should be introduced in stages. Do not start by designing a custom DTB unless the baseline boot path already works.

### Stage 1: Use The Simplest DTB Path

For early bring-up on QEMU `virt`, prefer the least custom path available:

- let QEMU provide the machine description,
- or use an existing Linux `virt`-compatible DTB if the chosen flow expects an explicit DTB artifact.

The goal here is only to prove:

- TF-A boots,
- U-Boot runs,
- Linux can be launched.

At this point, the DTB is just a bring-up dependency, not a security artifact.

### Stage 2: Build DTBs From Linux Source

Once the baseline boot path works, build DTBs from the Linux tree so you have a reproducible DTB artifact to sign later.

From the Linux source tree:

```bash
cd /home/bikumar/workspace/PoC/secure_boot_vm/src/linux
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
make -j$(nproc) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- dtbs
```

This uses the Linux build system plus `dtc` to compile `.dts` files into `.dtb` files.

Generated DTBs will typically appear under:

```text
arch/arm64/boot/dts/
```

At this stage, identify the DTB that matches your QEMU `virt` bring-up path and copy it into `secure_boot_vm/images/` for repeatable use.

### Stage 3: Create A Custom DTS Only If Needed

If your verification flow requires a stable platform-owned device tree, create a custom `.dts` file after the baseline setup is already working.

You can either:

- add the DTS under the Linux source tree and let `make dtbs` build it,
- or maintain it under `secure_boot_vm/images/` or `secure_boot_vm/scripts/` and compile it directly with `dtc`.

Direct `dtc` build example:

```bash
dtc -I dts -O dtb -o board.dtb board.dts
```

This is useful if you want a small controlled DTB just for the QEMU secure-boot experiment.

### Stage 4: Make The DTB A Signed Boot Artifact

In the final design, the DTB must not be trusted as an unsigned side file.

The DTB should be packaged alongside:

- the Linux `Image`,
- the optional initramfs,
- the FIT metadata.

U-Boot should verify all of them through the signed FIT image before booting Linux.

This means the final trust rule is:

- unsigned external DTB: not acceptable,
- DTB inside signed FIT: acceptable.

### Recommended Device Tree Workflow

Use this order:

1. boot with the simplest existing QEMU/Linux DTB path,
2. build DTBs from Linux source using `make dtbs`,
3. choose or create the DTB you want to keep stable,
4. include that DTB in the signed FIT image,
5. verify that tampering with the DTB causes U-Boot to reject boot.

## Phase 7: Verify Linux Payloads In U-Boot

This is the cleanest part of the chain because U-Boot already supports it.

### 7.1 Enable U-Boot Verified Boot Features

In U-Boot config, you will need the FIT and signature options enabled. The exact symbols vary by version, but the important capabilities are:

- FIT image support
- FIT signature verification
- ECDSA support
- SHA-256 hashing

You will likely need to adjust U-Boot config via `menuconfig` or by editing the defconfig fragment.

### 7.2 Create a FIT Source File

Create an ITS file that references:

- Linux `Image`
- DTB
- optional initramfs

Then sign the FIT using the ECC private key from `keys/root_priv.pem`.

Conceptually:

```text
kernel.its -> mkimage -> signed fitImage
```

### 7.3 Embed Or Provide The Verification Key To U-Boot

U-Boot needs the public verification key. Common approaches are:

- embed the public key into U-Boot's control DTB,
- compile the public key into the U-Boot image or config.

For your use case, this is acceptable because stage 0 already authenticates U-Boot itself. Once U-Boot is trusted, the embedded public key it carries for kernel verification is trusted as part of U-Boot.

### 7.4 Test Failure Modes

You should explicitly test:

- kernel image modified after signing,
- DTB modified after signing,
- initramfs modified after signing,
- wrong public key in U-Boot,
- unsigned FIT image.

Success criterion:

- U-Boot refuses to boot Linux unless the signed FIT verifies cleanly.

## Phase 8: Verify U-Boot Before Execution

This is the stage that replaces the current host-side `stage0_verify.py` logic with a real boot-stage check.

### 8.1 Practical Reality

U-Boot cannot verify itself before execution. Verification must happen in:

- ROM,
- SPL,
- TF-A,
- or another earlier immutable/authenticated stage.

For a QEMU ARM64 chain, TF-A is the practical place to implement or integrate this.

### 8.2 Minimal First Implementation

The simplest real implementation is:

1. keep the eFuse model as `efuse/root_pubkey.sha256`,
2. add verification logic in TF-A or in a thin wrapper stage before jumping to BL33,
3. authenticate the root public key against the eFuse hash,
4. verify a signature over the U-Boot binary,
5. jump to U-Boot only if verification succeeds.

### 8.3 Two Ways To Implement It

#### Path A: Prototype In TF-A Source

Modify TF-A QEMU platform code to:

- bundle the expected eFuse-backed hash,
- load or access the root public key,
- verify the U-Boot signature,
- refuse handoff on failure.

This is the most direct match to your requested architecture.

#### Path B: Use a Custom BL33 Wrapper

Insert a tiny custom loader that:

- runs after TF-A setup,
- checks the U-Boot signature using the eFuse-anchored key hash,
- jumps to U-Boot on success.

This is often easier to reason about initially than modifying TF-A internals deeply.

Recommended order:

1. get signed FIT verification working in U-Boot first,
2. only then add BL33 authentication in TF-A or a wrapper stage.

## Phase 9: Model The eFuse In The Real VM Setup

For QEMU, the eFuse is still only a model. Keep it explicit and narrow:

- store only the hash of the root public key,
- treat it as immutable input to the earliest verification stage,
- do not let U-Boot or Linux modify it.

For early bring-up, the easiest form is:

- compiled constant in TF-A or the wrapper stage.

A slightly more realistic model is:

- a read-only file loaded by QEMU and mapped to a known region,
- platform code reads that region as the eFuse value.

Start with the compiled constant. It removes unnecessary variables.

## Phase 10: Integrate With The Existing PoC

The current PoC already gives you:

- ECC key generation,
- public-key hashing into a simulated eFuse,
- signature verification logic,
- negative testing logic for tampered payloads.

Reuse those ideas, but split responsibilities:

- keep [prepare_demo.sh](/home/bikumar/workspace/PoC/secure_boot_poc/scripts/prepare_demo.sh) as the simple reference,
- create new scripts under `secure_boot_vm/scripts/` for real source builds and image signing,
- keep the trust model documented in [SECURE_BOOT_POC.md](/home/bikumar/workspace/PoC/secure_boot_poc/SECURE_BOOT_POC.md#L11).

## Recommended Execution Order

Run the work in this order:

1. install packages
2. clone TF-A, U-Boot, and Linux
3. build and boot baseline TF-A + U-Boot
4. boot baseline Linux from U-Boot
5. create and verify a signed FIT image in U-Boot
6. test tamper failures for Linux payloads
7. add U-Boot authentication in TF-A or a wrapper stage
8. test tamper failures for U-Boot

Do not invert this order. Trying to add both verification layers before the plain boot path works will slow you down.

## Expected Deliverables

At the end of the process, you should have:

- a reproducible build tree under `secure_boot_vm/`
- a bootable QEMU ARM64 command
- a signed U-Boot artifact checked before execution
- a signed FIT image checked by U-Boot
- documented negative tests proving rejection of tampered U-Boot and kernel payloads

## Known Risks

- TF-A integration details vary by upstream revision.
- U-Boot verified-boot config symbols differ across versions.
- Linux bring-up can fail for reasons unrelated to secure boot.
- QEMU `virt` boot commands are sensitive to exact image format and load addresses.

Because of that, the baseline boot path is the first milestone, not the signature plumbing.

## Suggested Next Document

After you start the real VM work, create a second document:

`/home/bikumar/workspace/PoC/secure_boot_vm/docs/bringup-notes.md`

Track:

- exact git commits used
- exact build commands used
- exact QEMU launch command that works
- every failure and the fix applied

That will matter once TF-A, U-Boot, and Linux versions start diverging.
