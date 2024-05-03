#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2024 SUSE LLC
#
# Author: Roy Hopkins <roy.hopkins@suse.com>
#
# A script to post-process the header files generated with cbindgen
# to rename items which could not be directly handled by the
# cbindgen configuration files and annotations.
set -e

sed -i -e 's/INVALID = 0/IGVM_INVALID = 0/g' \
        -e 's/RESERVED_DO_NOT_USE = /IGVM_RESERVED_DO_NOT_USE = /g' \
        -e 's/RequiredMemoryFlags/IgvmRequiredMemoryFlags/g' \
        -e 's/MemoryMapEntryFlags/IgvmMemoryMapEntryFlags/g' \
        $1/igvm_defs.h

sed -i -e 's/  HEADER_SECTION_/  IGVM_HEADER_SECTION_/g' \
        $1/igvm.h
