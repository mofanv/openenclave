# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../hostcalls.edl host gen)

add_executable(hostcalls_host host.cpp ${gen})

target_include_directories(hostcalls_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hostcalls_host oehostapp)
target_compile_options(hostcalls_host PRIVATE -Wconversion -Wpointer-arith)
