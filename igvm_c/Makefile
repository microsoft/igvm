# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Roy Hopkins <rhopkins@suse.de>

API_DIR:=$(realpath $(shell dirname $(firstword $(MAKEFILE_LIST))))
IGVM_DIR := $(API_DIR)/..

ifdef RELEASE
TARGET_PATH="$(IGVM_DIR)/target_c/release"
else
TARGET_PATH="$(IGVM_DIR)/target_c/debug"
endif

CARGO=CARGO_TARGET_DIR=$(IGVM_DIR)/target_c cargo

FEATURES = "igvm-c"

RUST_SOURCE := $(IGVM_DIR)/igvm/src/c_api.rs $(IGVM_DIR)/igvm/src/lib.rs $(IGVM_DIR)/igvm_defs/src/lib.rs

all: include/igvm.h $(TARGET_PATH)/dump_igvm test

$(TARGET_PATH)/libigvm.a:
	$(CARGO) build --features $(FEATURES) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml

$(TARGET_PATH)/libigvm_defs.rlib:
	$(CARGO) build --manifest-path=$(IGVM_DIR)/igvm_defs/Cargo.toml

$(TARGET_PATH)/test_data:
	$(CARGO) build --manifest-path=$(IGVM_DIR)/igvm_c/test_data/Cargo.toml

include/igvm.h: $(RUST_SOURCE)
	cbindgen -c $(API_DIR)/cbindgen_igvm.toml $(IGVM_DIR)/igvm -o "$(API_DIR)/include/igvm.h"
	cbindgen -c $(API_DIR)/cbindgen_igvm_defs.toml $(IGVM_DIR)/igvm_defs -o "$(API_DIR)/include/igvm_defs.h"

$(TARGET_PATH)/dump_igvm: $(API_DIR)/include/igvm.h $(API_DIR)/sample/dump_igvm.c $(TARGET_PATH)/libigvm.a
	cc -g3 -O0 -I $(API_DIR) -L $(TARGET_PATH) -o $@ $^ -ligvm -lcunit

$(TARGET_PATH)/igvm_test: $(API_DIR)/include/igvm.h $(API_DIR)/tests/igvm_test.c $(TARGET_PATH)/libigvm.a
	cc -g3 -O0 -I $(API_DIR) -L $(TARGET_PATH) -o $@ $^ -ligvm -lcunit

$(TARGET_PATH)/igvm.bin: $(TARGET_PATH)/test_data
	$(TARGET_PATH)/test_data $(TARGET_PATH)/igvm.bin

test: $(TARGET_PATH)/igvm_test $(TARGET_PATH)/igvm.bin
	$(TARGET_PATH)/igvm_test $(TARGET_PATH)/igvm.bin
	$(CARGO) test --features $(FEATURES) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml

clean:
	$(CARGO) clean --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml
	$(CARGO) clean --manifest-path=$(IGVM_DIR)/igvm_defs/Cargo.toml
	rm -f include/igvm.h include/igvm_defs.h $(TARGET_PATH)/dump_igvm $(TARGET_PATH)/test_data $(TARGET_PATH)/igvm.bin