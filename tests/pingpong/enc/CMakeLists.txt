# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../pingpong.edl enclave gen)
add_executable(pingpong_enc
    enc.cpp
    ${gen}
    )

target_include_directories(pingpong_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong_enc oeenclave)
target_compile_options(pingpong_enc PRIVATE -Wconversion -Wpointer-arith)
