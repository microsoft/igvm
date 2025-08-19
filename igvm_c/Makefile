# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Roy Hopkins <rhopkins@suse.de>

API_DIR:=$(realpath $(shell dirname $(firstword $(MAKEFILE_LIST))))
IGVM_DIR := $(API_DIR)/..
TARGET_DIR ?= target_c
EXE =

PREFIX ?= /usr
DESTDIR ?=

CFLAGS ?= -g3 -O0

CARGO=CARGO_TARGET_DIR=$(IGVM_DIR)/$(TARGET_DIR) cargo
CARGO_BUILD_HOST := $(shell $(CARGO) -Vv | sed -n 's,^host: ,,p')

FEATURES = "igvm-c"
PROFILE = $(if $(RELEASE),release,debug)

TARGET_PATH = "$(IGVM_DIR)/$(TARGET_DIR)/$(CARGO_BUILD_TARGET)/$(PROFILE)"
LIB_PATH = "$(IGVM_DIR)/$(TARGET_DIR)/$(or $(CARGO_BUILD_TARGET),$(CARGO_BUILD_HOST))/$(PROFILE)"

RUST_SOURCE := $(IGVM_DIR)/igvm/src/c_api.rs $(IGVM_DIR)/igvm/src/lib.rs $(IGVM_DIR)/igvm_defs/src/lib.rs
LIBIGVM = $(LIB_PATH)/libigvm.a
UNINSTALLED_PC = $(LIB_PATH)/igvm-uninstalled.pc
IGVM_LIBS = $(shell pkg-config --libs --static $(UNINSTALLED_PC))
IGVM_LIBS_STATIC = $(subst $(IGVM_LIBS), -ligvm, $(LIBIGVM))

# Determine igvm crate version from Cargo.toml
VERSION = $(shell grep -oP "(?<=version = \").+(?=\")" $(IGVM_DIR)/igvm/Cargo.toml)

.PHONY: all build test clean install

all: build test

build: $(API_DIR)/include/igvm.h $(TARGET_PATH)/dump_igvm$(EXE)

$(LIBIGVM):
	$(CARGO) cbuild --prefix $(PREFIX) --features $(FEATURES) $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml

$(TARGET_PATH)/libigvm_defs.rlib:
	$(CARGO) build $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm_defs/Cargo.toml

$(TARGET_PATH)/test_data$(EXE):
	$(CARGO) build $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm_c/test_data/Cargo.toml

$(API_DIR)/include/igvm.h: $(RUST_SOURCE)
	cbindgen -q -c $(API_DIR)/cbindgen_igvm.toml $(IGVM_DIR)/igvm -o "$(API_DIR)/include/igvm.h"
	cbindgen -q -c $(API_DIR)/cbindgen_igvm_defs.toml $(IGVM_DIR)/igvm_defs -o "$(API_DIR)/include/igvm_defs.h"
	$(API_DIR)/scripts/post_process.sh "$(API_DIR)/include"

$(TARGET_PATH)/dump_igvm$(EXE): $(API_DIR)/sample/dump_igvm.c $(API_DIR)/include/igvm.h $(LIBIGVM)
	$(CC) $(CFLAGS) -I $(API_DIR) -o $@ $< $(IGVM_LIBS) $(LDFLAGS)

$(TARGET_PATH)/igvm_test$(EXE): $(API_DIR)/tests/igvm_test.c $(API_DIR)/include/igvm.h $(LIBIGVM)
	$(CC) $(CFLAGS) -I $(API_DIR) -o $@ $< -lcunit $(IGVM_LIBS_STATIC) $(LDFLAGS)

$(TARGET_PATH)/igvm.bin: $(TARGET_PATH)/test_data$(EXE)
	$(TARGET_PATH)/test_data$(EXE) $(TARGET_PATH)/igvm.bin

test: $(TARGET_PATH)/igvm_test$(EXE) $(TARGET_PATH)/igvm.bin
	$(TARGET_PATH)/igvm_test$(EXE) $(TARGET_PATH)/igvm.bin
	$(CARGO) test --features $(FEATURES) $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml

clean:
	$(CARGO) clean $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml
	$(CARGO) clean $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm_defs/Cargo.toml
	rm -f $(API_DIR)/include/igvm.h $(API_DIR)/include/igvm_defs.h $(TARGET_PATH)/dump_igvm$(EXE) $(TARGET_PATH)/test_data$(EXE) $(TARGET_PATH)/igvm.bin

install: build
	mkdir -p $(DESTDIR)/$(PREFIX)/include/igvm
	install -m 644 $(IGVM_DIR)/igvm_c/include/* $(DESTDIR)/$(PREFIX)/include/igvm
	$(CARGO) cinstall --destdir "$(DESTDIR)" --prefix "$(PREFIX)" --features $(FEATURES) $(EXTRA_PARAMS) --manifest-path=$(IGVM_DIR)/igvm/Cargo.toml
	mkdir -p $(DESTDIR)/$(PREFIX)/bin/
	install -m 755 $(TARGET_PATH)/dump_igvm$(EXE) $(DESTDIR)/$(PREFIX)/bin/
