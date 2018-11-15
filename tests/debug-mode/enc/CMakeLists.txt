# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(no_debug_enc SHARED enc.c props.c)

target_make_enclave(no_debug_enc sign.conf)

add_library(debug_enc SHARED enc.c props-debug.c)

target_make_enclave(debug_enc sign-debug.conf)

target_link_libraries(no_debug_enc oeenclave)
target_link_libraries(debug_enc oeenclave)
