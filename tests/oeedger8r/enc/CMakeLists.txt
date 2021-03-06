# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../edl/all.edl 
    enclave
    all_t
    --edl-search-dir ../moreedl
)

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../moreedl/bar.edl 
    enclave-headers
    bar_t
)

add_executable(edl_enc
    bar.cpp
    config.cpp
    foo.cpp
    testarray.cpp
    testbasic.cpp 
    testenum.cpp 
    testforeign.cpp
    testpointer.cpp
    teststring.cpp
    teststruct.cpp
    ${all_t}
    ${bar_t}
    )

target_include_directories(edl_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_property(SOURCE ${edl_src} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wconversion -Wpointer-arith")

set_property(
    TARGET edl_enc
    PROPERTY CXX_STANDARD 11
)

target_link_libraries(edl_enc oelibcxx oeenclave)
