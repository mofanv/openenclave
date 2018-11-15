# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper function to create enclave binary
#
# Generates a target for an enclave binary
#
# Usage:
#
#	target_make_enclave(
#		<name> <signconffile> <signkeyfile>
#		source1 [source2...]
#
# Target properties can be set on <name>, see add_executable for details.
#
# Restrictions: A number of subtleties are not handled, such as
# - RUNTIME_OUTPUT_DIRECTORY property is not handled correctly
# - the resulting binary name is not reflected by the target
#   (complicating install rules)
#
function(target_make_enclave BIN SIGNCONF)
#set_property(TARGET ${BIN} PROPERTY
#    PREFIX "")
#set_property(TARGET ${BIN} PROPERTY SUFFIX "")
	# custom rule to generate signing key
	add_custom_command(OUTPUT ${BIN}-private.pem
		COMMAND openssl genrsa -out ${BIN}-private.pem -3 3072
		)

	# custom rule to sign the binary
	add_custom_command(OUTPUT ${BIN}.signed.so
		COMMAND oesign $<TARGET_FILE:${BIN}> ${SIGNCONF} ${CMAKE_CURRENT_BINARY_DIR}/${BIN}-private.pem
		DEPENDS oesign ${BIN} ${SIGNCONF} ${BIN}-private.pem
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)

	# signed binary is a default target
	add_custom_target(${BIN}-signed ALL
		DEPENDS ${BIN}.signed.so
		)
endfunction(target_make_enclave)
