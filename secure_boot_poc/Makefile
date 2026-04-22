ROOT := $(CURDIR)
PYTHON := python3

.PHONY: prepare verify-stage0 verify-uboot verify demo clean

prepare:
	bash ./scripts/prepare_demo.sh

verify-stage0:
	$(PYTHON) ./scripts/stage0_verify.py

verify-uboot:
	$(PYTHON) ./scripts/uboot_verify.py

verify: verify-stage0 verify-uboot

demo: prepare verify

clean:
	rm -rf artifacts efuse keys runtime
