# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper function to sign an enclave binary.
#
# Usage:
#
#	target_make_enclave(<target> <signconffile>)
#
# The target must already exist and should be a shared object (an
# enclave).
#
# Given <target> and <signconffile>, this function adds custom
# commands to generate a signing key and call `oesign` to sign the
# target, resulting in `<target>.signed.so`. It also adds
# `<target>_signed` as an imported target so that it can be referenced
# later in the CMake graph.
#
# TODO: (1) Rename this to `target_sign_enclave` since it does not
# make an enclave.
# TODO: (2) Use `cmake_parse_arguments` to fix the argument names.
# TODO: (3) Add an optional argument to accept a given signing key
# instead of generating one.
# TODO: (4) Replace the name guessing logic.
# TODO: (5) Setup the dependency using `${BIN}_signed` instead of the
# default custom target.
function(target_make_enclave BIN SIGNCONF)
  # Generate the signing key.
  add_custom_command(OUTPUT ${BIN}-private.pem
    COMMAND openssl genrsa -out ${BIN}-private.pem -3 3072)

  # TODO: Get this name intelligently (somehow use $<TARGET_FILE> with
  # `.signed` injected).
  set(SIGNED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/lib${BIN}.signed.so)

  # Sign the enclave using `oesign`.
  add_custom_command(OUTPUT ${SIGNED_LOCATION}
    COMMAND oesign $<TARGET_FILE:${BIN}> ${SIGNCONF} ${CMAKE_CURRENT_BINARY_DIR}/${BIN}-private.pem
    DEPENDS oesign ${BIN} ${SIGNCONF} ${BIN}-private.pem
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  # Import the generated signed enclave so we can reference it with
  # `$<TARGET_FILE>` later.
  add_library(${BIN}_signed SHARED IMPORTED GLOBAL)
  set_target_properties(${BIN}_signed PROPERTIES
    IMPORTED_LOCATION ${SIGNED_LOCATION})

  # Add a custom target with `ALL` semantics so these targets are always built.
  add_custom_target(${BIN}_signed_target ALL DEPENDS ${SIGNED_LOCATION})
endfunction()
