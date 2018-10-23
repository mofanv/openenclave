// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>

uint64_t _rdrand(void)
{
    uint64_t r;
    __asm__ volatile(
        "1%=: \n\t"
        "rdrand %0\n\t"
        "jnc 1%=\n\t"
        : "=r"(r)
        :
        :);

    return r;
}
