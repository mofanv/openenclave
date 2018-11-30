/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/enclave.h>
#include <sgx_utils.h>
#include <mbedtls/x509_crt.h>

#include "../oeresult.h"
#include "cyres_optee.h"
#include "enclavelibc.h"

oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    if (report_buffer == NULL || report_buffer_size == NULL)
        return OE_INVALID_PARAMETER;

    return get_cyres_cert_chain(report_buffer, report_buffer_size);
}

oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t oeResult = OE_OK;
    if (parsed_report != NULL)
    {
        oeResult = oe_parse_report(report, report_size, parsed_report);
        if (oeResult != OE_OK)
        {
            return oeResult;
        }
    }

    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    int res = mbedtls_x509_crt_parse(&chain, report, report_size);
    if (res != 0)
    {
        oeResult = OE_FAILURE;
        goto Cleanup;
    }

    if (chain.next == NULL ||
        chain.next->next != NULL)
    {
        oeResult = OE_FAILURE;
        goto Cleanup;
    }

    uint32_t validation_flags = 0;
    res = mbedtls_x509_crt_verify(
        &chain, chain.next, NULL, NULL, &validation_flags, NULL, NULL);
    if (res != 0 || validation_flags != 0)
    {
        oeResult = OE_FAILURE;
        goto Cleanup;
    }

Cleanup:
    mbedtls_x509_crt_free(&chain);

    return oeResult;
}