# Makefile — Resolution Scope store compartment (seL4 Microkit, Option B)
#
# Copyright 2026, IT Help San Diego Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the two-PD store-compartment system (engine stub → passive store) into
# a bootable Microkit loader.img. Mirrors the SDK passive_server example.
#
# Usage:
#   make BUILD_DIR=build \
#        MICROKIT_SDK=/path/to/microkit-sdk-2.3.0 \
#        MICROKIT_BOARD=qemu_virt_aarch64 \
#        MICROKIT_CONFIG=debug
#
#   Run (Microkit manual §8.13):
#   qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 \
#     -nographic -serial mon:stdio \
#     -device loader,file=build/loader.img,addr=0x70000000,cpu-num=0 -m size=2G

ifeq ($(strip $(BUILD_DIR)),)
$(error BUILD_DIR must be specified)
endif
ifeq ($(strip $(MICROKIT_SDK)),)
$(error MICROKIT_SDK must be specified)
endif
ifeq ($(strip $(MICROKIT_BOARD)),)
$(error MICROKIT_BOARD must be specified)
endif
ifeq ($(strip $(MICROKIT_CONFIG)),)
$(error MICROKIT_CONFIG must be specified)
endif

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

ARCH := ${shell grep 'CONFIG_SEL4_ARCH  ' $(BOARD_DIR)/include/kernel/gen_config.h | cut -d' ' -f4}

ifeq ($(ARCH),aarch64)
  TARGET_TRIPLE := aarch64-none-elf
  CFLAGS_ARCH := -mstrict-align
else ifeq ($(ARCH),riscv64)
  TARGET_TRIPLE := riscv64-unknown-elf
  CFLAGS_ARCH := -march=rv64imafdc_zicsr_zifencei -mabi=lp64d
else ifeq ($(ARCH),x86_64)
  TARGET_TRIPLE := x86_64-linux-gnu
  CFLAGS_ARCH := -march=x86-64 -mtune=generic
else
$(error Unsupported ARCH)
endif

CC := $(TARGET_TRIPLE)-gcc
LD := $(TARGET_TRIPLE)-ld
AS := $(TARGET_TRIPLE)-as

MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit

STORE_OBJS := store.o
ENGINE_OBJS := engine.o
IMAGES := store.elf engine.elf

CFLAGS := -nostdlib -ffreestanding -g -O3 -Wall -Wno-unused-function -Werror \
          -I$(BOARD_DIR)/include $(CFLAGS_ARCH)
LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := -lmicrokit -Tmicrokit.ld

IMAGE_FILE = $(BUILD_DIR)/loader.img
REPORT_FILE = $(BUILD_DIR)/report.txt

all: $(IMAGE_FILE)

$(BUILD_DIR)/%.o: %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/store.elf: $(addprefix $(BUILD_DIR)/, $(STORE_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/engine.elf: $(addprefix $(BUILD_DIR)/, $(ENGINE_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(IMAGE_FILE) $(REPORT_FILE): $(addprefix $(BUILD_DIR)/, $(IMAGES)) dns_sovereign_compartment.system
	$(MICROKIT_TOOL) dns_sovereign_compartment.system --search-path $(BUILD_DIR) \
		--board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
		-o $(IMAGE_FILE) -r $(REPORT_FILE)

qemu: $(IMAGE_FILE)
	qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 \
		-nographic -serial mon:stdio \
		-device loader,file=$(IMAGE_FILE),addr=0x70000000,cpu-num=0 -m size=2G

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all qemu clean
