// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

.text
        .globl  _rdrand
_rdrand:
 pushq   %rbp
 movq    %rsp, %rbp
111:
        rdrand %rax
        jnc 111
leave
ret

