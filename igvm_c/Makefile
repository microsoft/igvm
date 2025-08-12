# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Roy Hopkins <rhopkins@suse.de>

API_DIR:=$(realpath $(shell dirname $(firstword $(MAKEFILE_LIST))))
IGVM_DIR := $(API_DIR)/..
TARGET_DIR ?= target_c

PREFIX ?= /usr
DESTDIR ?=

CFLAGS ?= -g3 -O0
LDFLAGS += -L $(TARGET_PATH)

CARGO=CARGO_TARGET_DIR=$(IGVM_DIR)/$(TARGET_DIR) cargo
CARGO_BUILD_HOST := $(shell $(CARGO) -Vv | sed -n 's,^host: ,,p')

FEATURES = "igvm-c"
PROFILE = $(if $(RELEASE),release,debug)

TARGET_PATH = "$(IGVM_DIR)/$(TARGET_DIR)/$(CARGO_BUILD_TARGET)/$(PROFILE)"
LIB_PATH = "$(IGVM_DIR)/$(TARGET_DIR)/$(or $(CARGO_BUILD_TARGET),$(CARGO_BUILD_HOST))/$(PROFILE)"

RUST_SOURCE := $(IGVM_DIR)/igvm/src/c_api.rs $(IGVM_DIR)/igvm/src/lib.rs $(IGVM_DIR)/igvm_defs/src/lib.rs
LIBIGVM = $(LIB_PATH)/libigvm.a

# Determine igvm crate version from Cargo.toml
VERSION = $(shell grep -oP "(?<=version = \").+(?=\")" $(IGVM_DIR)/igvm/Cargo.toml)

.PHONY: all build test clean install

all: build test

build: $(API_DIR)/include/igvm.h $(TARGET_PATH)/dump_igvm

$(LIBIGVM):
	$(CARGO) cbuild --prefix $(PREFIX) --features $(FEATURES) $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml

$(TARGET_PATH)/libigvm_defs.rlib:
	$(CARGO) build $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm_defs/Cargo.toml

$(TARGET_PATH)/test_data:
	$(CARGO) build $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm_c/test_data/Cargo.toml

$(API_DIR)/include/igvm.h: $(RUST_SOURCE)
	cbindgen -q -c $(API_DIR)/cbindgen_igvm.toml $(IGVM_DIR)/igvm -o "$(API_DIR)/include/igvm.h"
	cbindgen -q -c $(API_DIR)/cbindgen_igvm_defs.toml $(IGVM_DIR)/igvm_defs -o "$(API_DIR)/include/igvm_defs.h"
	$(API_DIR)/scripts/post_process.sh "$(API_DIR)/include"

$(TARGET_PATH)/dump_igvm: $(API_DIR)/sample/dump_igvm.c $(API_DIR)/include/igvm.h $(LIBIGVM)
	$(CC) $(CFLAGS) -I $(API_DIR) -o $@ $< $(LIBIGVM) -ldl -pthread -lutil -lrt $(LDFLAGS)

$(TARGET_PATH)/igvm_test: $(API_DIR)/tests/igvm_test.c $(API_DIR)/include/igvm.h $(LIBIGVM)
	$(CC) $(CFLAGS) -I $(API_DIR) -o $@ $< $(LIBIGVM) -lcunit -ldl -pthread -lutil -lrt $(LDFLAGS)

$(TARGET_PATH)/igvm.bin: $(TARGET_PATH)/test_data
	$(TARGET_PATH)/test_data $(TARGET_PATH)/igvm.bin

test: $(TARGET_PATH)/igvm_test $(TARGET_PATH)/igvm.bin
	$(TARGET_PATH)/igvm_test $(TARGET_PATH)/igvm.bin
	$(CARGO) test --features $(FEATURES) $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml

clean:
	$(CARGO) clean $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml
	$(CARGO) clean $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm_defs/Cargo.toml
	rm -f $(API_DIR)/include/igvm.h $(API_DIR)/include/igvm_defs.h $(TARGET_PATH)/dump_igvm $(TARGET_PATH)/test_data $(TARGET_PATH)/igvm.bin

install: build
	mkdir -p $(DESTDIR)/$(PREFIX)/include/igvm
	install -m 644 $(IGVM_DIR)/igvm_c/include/* $(DESTDIR)/$(PREFIX)/include/igvm
	$(CARGO) cinstall --destdir "$(DESTDIR)" --prefix "$(PREFIX)" --features $(FEATURES) $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml
	mkdir -p $(DESTDIR)/$(PREFIX)/bin/
	install -m 755 $(TARGET_PATH)/dump_igvm $(DESTDIR)/$(PREFIX)/bin/
