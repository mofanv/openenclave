/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>

#include <mbedtls/x509_crt.h>

#include <RiotStatus.h>
#include <RiotEcc.h>
#include <RiotCrypt.h>
#include <TcpsId.h>

#ifndef _In_
#include "sal_unsup.h"
#endif

unsigned char tcpsOid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x02};

// Adopted from mbedtls
oe_result_t
GetClaimOidData(
    uint8_t * DerExtensionBuffer,
    size_t DerExtensionBufferLen,
    uint8_t** ClaimOidData,
    size_t* ClaimOidDataLen)
{
    int ret;
    oe_result_t result = OE_FAILURE;
    size_t len;
    unsigned char** p = &DerExtensionBuffer;
    const unsigned char* end = DerExtensionBuffer + DerExtensionBufferLen;
    unsigned char *end_ext_data, *end_ext_octet;
    
    *ClaimOidData = NULL;

    if ((ret = mbedtls_asn1_get_tag(
             p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) !=
        0)
        return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

    while (*p < end)
    {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        mbedtls_x509_buf extn_oid = {0, 0, NULL};
        int is_critical = 0; /* DEFAULT FALSE */
        int ext_type = 0;

        if ((ret = mbedtls_asn1_get_tag(
                 p,
                 end,
                 &len,
                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        end_ext_data = *p + len;

        /* Get extension ID */
        if ((ret = mbedtls_asn1_get_tag(
                 p, end_ext_data, &extn_oid.len, MBEDTLS_ASN1_OID)) != 0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        extn_oid.tag = MBEDTLS_ASN1_OID;
        extn_oid.p = *p;
        *p += extn_oid.len;

        /* Get optional critical */
        if ((ret = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical)) != 0 &&
            (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG))
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        /* Data should be octet string type */
        if ((ret = mbedtls_asn1_get_tag(
                 p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        end_ext_octet = *p + len;

        if (end_ext_octet != end_ext_data)
            return (
                MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);

        if (extn_oid.len != sizeof(tcpsOid) ||
            memcmp(extn_oid.p, tcpsOid, sizeof(tcpsOid)))
        {
            *p = end_ext_octet;
            continue;
        }

        if ((ret = mbedtls_asn1_get_tag(
                 p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        if (end_ext_octet != *p + len)
            return (
                MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);

        *ClaimOidData = *p;
        *ClaimOidDataLen = len;
        result = OE_OK;
        break;
    }

    return result;
}

static oe_result_t get_claims(
    mbedtls_x509_crt *cert,
    uint8_t *signer_id_buffer,
    size_t signed_id_buffer_size,
    uint8_t* unique_id_buffer,
    size_t unique_id_buffer_size)
{
    uint8_t* claimOidData;
    size_t claimOidDataLen;
    oe_result_t result = GetClaimOidData(
        cert->v3_ext.p, cert->v3_ext.len, &claimOidData, &claimOidDataLen);
    if (result != OE_OK)
    {
        goto Cleanup;
    }

    const uint8_t* valueBuffer;
    size_t valueBufferLen;
    RIOT_STATUS status = GetClaim(
        claimOidData,
        claimOidDataLen,
        TCPS_IDENTITY_MAP_AUTH,
        &valueBuffer,
        &valueBufferLen);
    if (status != RIOT_SUCCESS)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    status = RiotCrypt_Hash(
        signer_id_buffer,
        signed_id_buffer_size,
        valueBuffer,
        valueBufferLen);
    if (status != RIOT_SUCCESS)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    status = GetClaim(
        claimOidData,
        claimOidDataLen,
        TCPS_IDENTITY_MAP_FWID,
        &valueBuffer,
        &valueBufferLen);
    if (status == RIOT_SUCCESS)
    {
        if (valueBufferLen != unique_id_buffer_size)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }

        memcpy(unique_id_buffer, valueBuffer, valueBufferLen);
    }
    else
    {
        status = GetClaim(
            claimOidData,
            claimOidDataLen,
            TCPS_IDENTITY_MAP_PUBKEY,
            &valueBuffer,
            &valueBufferLen);
        if (status != RIOT_SUCCESS)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }

        status = RiotCrypt_Hash(
            unique_id_buffer,
            unique_id_buffer_size,
            valueBuffer,
            valueBufferLen);
        if (status != RIOT_SUCCESS)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
    }

Cleanup:
    return result;
}

oe_result_t oe_parse_report(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_ oe_report_t* parsed_report)
{
    oe_result_t result = OE_OK;
    
    if (report == NULL || report_size == 0 || parsed_report == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    parsed_report->size = sizeof(*parsed_report);
    parsed_report->type = OE_ENCLAVE_TYPE_TRUSTZONE;

    parsed_report->enclave_report_size = report_size;
    parsed_report->enclave_report = (uint8_t*)&report;

    parsed_report->report_data_size = 0;
    parsed_report->report_data = NULL;

    parsed_report->identity.id_version = 0;
    parsed_report->identity.security_version = 0;

    parsed_report->identity.attributes = 0;
    // TODO: add support for OE_REPORT_ATTRIBUTES_*

    memset(
        parsed_report->identity.product_id,
        0,
        sizeof(parsed_report->identity.product_id));

    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    int res = mbedtls_x509_crt_parse(&chain, report, report_size);
    if (res != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    result = get_claims(
        &chain,
        parsed_report->identity.signer_id,
        sizeof(parsed_report->identity.signer_id),
        parsed_report->identity.unique_id,
        sizeof(parsed_report->identity.unique_id));
    if (result != OE_OK)
    {
        goto Cleanup;
    }

    if (chain.next == NULL)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    result = get_claims(
        chain.next,
        parsed_report->identity.device_signer_id,
        sizeof(parsed_report->identity.device_signer_id),
        parsed_report->identity.device_unique_id,
        sizeof(parsed_report->identity.device_unique_id));
    if (result != OE_OK)
    {
        goto Cleanup;
    }

Cleanup:

    mbedtls_x509_crt_free(&chain);

    return result;
}

oe_result_t oe_get_target_info_v2(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Outptr_ void** target_info_buffer,
    _Out_ size_t* target_info_size)
{
    /* Not yet supported */
    return OE_UNSUPPORTED;
}

oe_result_t oe_get_target_info_v1(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_writes_bytes_(*target_info_size) void* target_info_buffer,
    _Inout_ size_t* target_info_size)
{
    return OE_UNSUPPORTED;
}

void oe_free_target_info(_In_ void* target_info_buffer)
{
    return;
}
