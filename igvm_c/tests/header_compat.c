/*
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Copyright (c) Microsoft Corporation.
 */

#include <stddef.h>
#include "include/igvm.h"

/* Match the OpenSSL function names without adding a test dependency. */
unsigned char *SHA256(const unsigned char *data, size_t length, unsigned char *digest);
unsigned char *SHA384(const unsigned char *data, size_t length, unsigned char *digest);
unsigned char *SHA512(const unsigned char *data, size_t length, unsigned char *digest);

enum ConsumerPageType {
    NORMAL,
    VMSA,
    UNMEASURED,
    SECRETS,
    CPUID
};

IgvmCcaHashAlgorithm header_hash_algorithms[] = {
    IGVM_CCA_HASH_ALGORITHM_SHA256,
    IGVM_CCA_HASH_ALGORITHM_SHA384,
    IGVM_CCA_HASH_ALGORITHM_SHA512
};
