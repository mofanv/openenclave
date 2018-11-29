// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/asn1.h"
#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/asn1.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

static const uint32_t trace_flag = OE_LOG_FLAGS_OTHERS;

OE_STATIC_ASSERT(MBEDTLS_ASN1_CONSTRUCTED == OE_ASN1_TAG_CONSTRUCTED);
OE_STATIC_ASSERT(MBEDTLS_ASN1_SEQUENCE == OE_ASN1_TAG_SEQUENCE);
OE_STATIC_ASSERT(MBEDTLS_ASN1_INTEGER == OE_ASN1_TAG_INTEGER);
OE_STATIC_ASSERT(MBEDTLS_ASN1_OID == OE_ASN1_TAG_OID);
OE_STATIC_ASSERT(MBEDTLS_ASN1_OCTET_STRING == OE_ASN1_TAG_OCTET_STRING);

OE_INLINE const uint8_t* _end(const oe_asn1_t* asn1)
{
    return asn1->data + asn1->length;
}

/* Cast away constness for MBEDTLS ASN.1 functions */
OE_INLINE uint8_t** _pptr(const oe_asn1_t* asn1)
{
    return (uint8_t**)&asn1->ptr;
}

OE_INLINE bool _is_valid(const oe_asn1_t* asn1)
{
    if (!asn1 || !asn1->data || !asn1->length || !asn1->ptr)
        return false;

    if (!(asn1->ptr >= asn1->data && asn1->ptr <= _end(asn1)))
        return false;

    return true;
}

static oe_result_t _get_length(oe_asn1_t* asn1, size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;

    if (mbedtls_asn1_get_len(_pptr(asn1), _end(asn1), length) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_raw(
    oe_asn1_t* asn1,
    oe_asn1_tag_t* tag,
    const uint8_t** data,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    bool constructed;

    if (data)
        *data = NULL;

    if (length)
        *length = 0;

    if (!_is_valid(asn1) || !tag || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get_tag(asn1, &constructed, tag));
    OE_CHECK(_get_length(asn1, length));
    *data = asn1->ptr;
    asn1->ptr += *length;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_sequence(oe_asn1_t* asn1, oe_asn1_t* sequence)
{
    oe_result_t result = OE_UNEXPECTED;
    bool constructed;
    oe_asn1_tag_t tag;
    size_t length;

    if (sequence)
        oe_memset(sequence, 0, sizeof(oe_asn1_t));

    if (!_is_valid(asn1) || !sequence)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get_tag(asn1, &constructed, &tag));

    if (!constructed || tag != OE_ASN1_TAG_SEQUENCE)
        OE_RAISE(OE_FAILURE);

    OE_CHECK(_get_length(asn1, &length));

    oe_asn1_init(sequence, asn1->ptr, length);

    asn1->ptr += length;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_integer(oe_asn1_t* asn1, int* value)
{
    oe_result_t result = OE_UNEXPECTED;

    if (value)
        *value = 0;

    if (!_is_valid(asn1) || !value)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (mbedtls_asn1_get_int(_pptr(asn1), _end(asn1), value) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_oid(oe_asn1_t* asn1, oe_oid_string_t* oid)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t length;
    oe_asn1_tag_t tag = MBEDTLS_ASN1_OID;

    if (oid)
        oe_memset(oid, 0, sizeof(oe_oid_string_t));

    if (!_is_valid(asn1) || !oid)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (mbedtls_asn1_get_tag(_pptr(asn1), _end(asn1), &length, tag) != 0)
        OE_RAISE(OE_FAILURE);

    if (tag != MBEDTLS_ASN1_OID)
        OE_RAISE(OE_FAILURE);

    /* Convert OID to string */
    {
        mbedtls_x509_buf buf;
        int r;

        buf.tag = tag;
        buf.len = length;
        buf.p = (uint8_t*)asn1->ptr;

        r = mbedtls_oid_get_numeric_string(oid->buf, sizeof(*oid), &buf);

        if (r < 0)
            OE_RAISE(OE_FAILURE);
    }

    asn1->ptr += length;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_octet_string(
    oe_asn1_t* asn1,
    const uint8_t** data,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_asn1_tag_t tag = MBEDTLS_ASN1_OCTET_STRING;

    if (data)
        *data = NULL;

    if (length)
        *length = 0;

    if (!_is_valid(asn1) || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (mbedtls_asn1_get_tag(_pptr(asn1), _end(asn1), length, tag) != 0)
        OE_RAISE(OE_FAILURE);

    *data = asn1->ptr;
    asn1->ptr += *length;

    result = OE_OK;

done:
    return result;
}
