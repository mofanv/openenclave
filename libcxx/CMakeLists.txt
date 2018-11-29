# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# CMake project for CXX lib - archive the objects from external
# libcxx, libcxxrt, libunwind and wrap in easy-to-use CMake target

add_library(oelibcxx STATIC)

target_link_libraries(oelibcxx
  PUBLIC cxxrt unwind oelibcxx_cxx)

set_property(TARGET oelibcxx
  PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/enclave)

install(TARGETS oelibcxx EXPORT openenclave
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
