# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../mbed.edl host gen)

add_executable(libmbedtest_host host.c ocalls.c ${gen})

target_compile_options(libmbedtest_host PRIVATE -Wno-error -Wconversion -Wpointer-arith)

target_include_directories(libmbedtest_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(libmbedtest_host oehostapp)
