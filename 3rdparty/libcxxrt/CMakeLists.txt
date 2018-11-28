# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Compile libcxx for Open Enclave. Some of these build rules emulate
# that found in the original sources, but instead this builds an object library.

add_library(cxxrt OBJECT
  libcxxrt/src/dynamic_cast.cc
  libcxxrt/src/exception.cc
  libcxxrt/src/guard.cc
  libcxxrt/src/stdexcept.cc
  libcxxrt/src/typeinfo.cc
  libcxxrt/src/memory.cc
  libcxxrt/src/auxhelper.cc
  libcxxrt/src/libelftc_dem_gnu3.c)

set_property(SOURCE libcxxrt/src/exception.cc PROPERTY COMPILE_FLAGS -Wno-unused-variable)

set_property(TARGET cxxrt PROPERTY POSITION_INDEPENDENT_CODE ON)

target_compile_options(cxxrt PRIVATE
  -Wno-tautological-compare
  -nostdinc
  $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>)

target_compile_definitions(cxxrt PRIVATE -D_GNU_SOURCE)

add_dependencies(cxxrt oelibc_includes)
target_include_directories(cxxrt PRIVATE ${OE_INCDIR}/openenclave/libc)
