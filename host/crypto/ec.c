// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/bits/raise.h>
#include <openssl/pem.h>
#include <string.h>
#include "init.h"
#include "key.h"

/*
**==============================================================================
**
** Provide definitions needed for key.c and include key.c.
**
**==============================================================================
*/

static const uint64_t _PRIVATE_KEY_MAGIC = 0x19a751419ae04bbc;
static const uint64_t _PUBLIC_KEY_MAGIC = 0xb1d39580c1f14c02;

/*
**==============================================================================
**
** Definitions below depend on definitions provided by key.c.
**
**==============================================================================
*/

OE_STATIC_ASSERT(sizeof(OE_PublicKey) <= sizeof(OE_ECPublicKey));
OE_STATIC_ASSERT(sizeof(OE_PublicKey) <= sizeof(OE_ECPublicKey));

/* Curve names, indexed by OE_ECType */
static const char* _curveNames[] = {
    "secp521r1" /* OE_EC_TYPE_SECP521R1 */
};

/* Convert ECType to curve name */
static const char* _ECTypeToString(OE_Type type)
{
    size_t index = (size_t)type;

    if (index >= OE_COUNTOF(_curveNames))
        return NULL;

    return _curveNames[index];
}

static OE_Result _WriteKey(BIO* bio, EVP_PKEY* pkey)
{
    OE_Result result = OE_UNEXPECTED;
    EC_KEY* ec = NULL;

    if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
        OE_RAISE(OE_FAILURE);

    if (!PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, 0, NULL))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    return result;
}

static OE_Result _GenerateKeyPair(
    OE_ECType type,
    OE_PrivateKey* privateKey,
    OE_PublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    int nid;
    EC_KEY* key = NULL;
    EVP_PKEY* pkey = NULL;
    BIO* bio = NULL;
    const char nullTerminator = '\0';
    const char* curveName;

    if (privateKey)
        memset(privateKey, 0, sizeof(*privateKey));

    if (publicKey)
        memset(publicKey, 0, sizeof(*publicKey));

    /* Check parameters */
    if (!privateKey || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(curveName = _ECTypeToString(type)))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Resolve the NID for this curve name */
    if ((nid = OBJ_txt2nid(curveName)) == NID_undef)
        OE_RAISE(OE_FAILURE);

    /* Create the key */
    if (!(key = EC_KEY_new_by_curve_name(nid)))
        OE_RAISE(OE_FAILURE);

    /* Set the EC named-curve flag */
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    /* Generate the public/private key pair */
    if (!EC_KEY_generate_key(key))
        OE_RAISE(OE_FAILURE);

    /* Create the privateKey key structure */
    if (!(pkey = EVP_PKEY_new()))
        OE_RAISE(OE_FAILURE);

    /* Initialize the privateKey key from the generated key pair */
    if (!EVP_PKEY_assign_EC_KEY(pkey, key))
        OE_RAISE(OE_FAILURE);

    /* Key will be released when pkey is released */
    key = NULL;

    /* Create privateKey key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
            OE_RAISE(OE_FAILURE);

        if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL))
            OE_RAISE(OE_FAILURE);

        if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
            OE_RAISE(OE_FAILURE);

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_FAILURE);

        if (OE_PrivateKeyReadPEM(
                (uint8_t*)mem->data,
                mem->length,
                privateKey,
                EVP_PKEY_EC,
                _PRIVATE_KEY_MAGIC) != OE_OK)
        {
            OE_RAISE(OE_FAILURE);
        }

        BIO_free(bio);
        bio = NULL;
    }

    /* Create publicKey key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
            OE_RAISE(OE_FAILURE);

        if (!PEM_write_bio_PUBKEY(bio, pkey))
            OE_RAISE(OE_FAILURE);

        if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
            OE_RAISE(OE_FAILURE);

        BIO_get_mem_ptr(bio, &mem);

        if (OE_PublicKeyReadPEM(
                (uint8_t*)mem->data,
                mem->length,
                publicKey,
                EVP_PKEY_EC,
                _PUBLIC_KEY_MAGIC) != OE_OK)
        {
            OE_RAISE(OE_FAILURE);
        }

        BIO_free(bio);
        bio = NULL;
    }

    result = OE_OK;

done:

    if (key)
        EC_KEY_free(key);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    if (result != OE_OK)
    {
        OE_PrivateKeyFree(privateKey, _PRIVATE_KEY_MAGIC);
        OE_PublicKeyFree(publicKey, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

static OE_Result _PublicKeyGetKeyBytes(
    const OE_PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t* data = NULL;
    EC_KEY* ec = NULL;
    int requiredSize;

    /* Check for invalid parameters */
    if (!publicKey || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the EC public key */
    if (!(ec = EVP_PKEY_get1_EC_KEY(publicKey->pkey)))
        OE_RAISE(OE_FAILURE);

    /* Set the required buffer size */
    if ((requiredSize = i2o_ECPublicKey(ec, NULL)) == 0)
        OE_RAISE(OE_FAILURE);

    /* If buffer is null or not big enough */
    if (!buffer || (*bufferSize < requiredSize))
    {
        *bufferSize = requiredSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Get the key bytes */
    if (!i2o_ECPublicKey(ec, &data))
        OE_RAISE(OE_FAILURE);

    /* Copy to caller's buffer */
    memcpy(buffer, data, requiredSize);
    *bufferSize = requiredSize;

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    if (data)
        free(data);

    return result;
}

static OE_Result _PublicKeyEqual(
    const OE_PublicKey* publicKey1,
    const OE_PublicKey* publicKey2,
    bool* equal)
{
    OE_Result result = OE_UNEXPECTED;
    EC_KEY* ec1 = NULL;
    EC_KEY* ec2 = NULL;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!OE_PublicKeyIsValid(publicKey1, _PUBLIC_KEY_MAGIC) ||
        !OE_PublicKeyIsValid(publicKey2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        ec1 = EVP_PKEY_get1_EC_KEY(publicKey1->pkey);
        ec2 = EVP_PKEY_get1_EC_KEY(publicKey2->pkey);
        const EC_GROUP* group1 = EC_KEY_get0_group(ec1);
        const EC_GROUP* group2 = EC_KEY_get0_group(ec2);
        const EC_POINT* point1 = EC_KEY_get0_public_key(ec1);
        const EC_POINT* point2 = EC_KEY_get0_public_key(ec2);

        /* Compare group and public key point */
        if (EC_GROUP_cmp(group1, group2, NULL) == 0 &&
            EC_POINT_cmp(group1, point1, point2, NULL) == 0)
        {
            *equal = true;
        }
    }

    result = OE_OK;

done:

    if (ec1)
        EC_KEY_free(ec1);

    if (ec2)
        EC_KEY_free(ec2);

    return result;
}

void OE_ECPublicKeyInit(OE_ECPublicKey* publicKey, EVP_PKEY* pkey)
{
    return OE_PublicKeyInit((OE_PublicKey*)publicKey, pkey, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPrivateKey* privateKey)
{
    return OE_PrivateKeyReadPEM(
        pemData,
        pemSize,
        (OE_PrivateKey*)privateKey,
        EVP_PKEY_EC,
        _PRIVATE_KEY_MAGIC);
}

OE_Result OE_ECPrivateKeyWritePEM(
    const OE_ECPrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return OE_PrivateKeyWritePEM(
        (const OE_PrivateKey*)privateKey,
        pemData,
        pemSize,
        _WriteKey,
        _PRIVATE_KEY_MAGIC);
}

OE_Result OE_ECPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPublicKey* publicKey)
{
    return OE_PublicKeyReadPEM(
        pemData,
        pemSize,
        (OE_PublicKey*)publicKey,
        EVP_PKEY_EC,
        _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECPublicKeyWritePEM(
    const OE_ECPublicKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return OE_PublicKeyWritePEM(
        (const OE_PublicKey*)privateKey, pemData, pemSize, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECPrivateKeyFree(OE_ECPrivateKey* privateKey)
{
    return OE_PrivateKeyFree((OE_PrivateKey*)privateKey, _PRIVATE_KEY_MAGIC);
}

OE_Result OE_ECPublicKeyFree(OE_ECPublicKey* publicKey)
{
    return OE_PublicKeyFree((OE_PublicKey*)publicKey, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECPrivateKeySign(
    const OE_ECPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    return OE_PrivateKeySign(
        (OE_PrivateKey*)privateKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PRIVATE_KEY_MAGIC);
}

OE_Result OE_ECPublicKeyVerify(
    const OE_ECPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    return OE_PublicKeyVerify(
        (OE_PublicKey*)publicKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECGenerateKeyPair(
    OE_ECType type,
    OE_ECPrivateKey* privateKey,
    OE_ECPublicKey* publicKey)
{
    return _GenerateKeyPair(
        type, (OE_PrivateKey*)privateKey, (OE_PublicKey*)publicKey);
}

OE_Result OE_ECPublicKeyGetKeyBytes(
    const OE_ECPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _PublicKeyGetKeyBytes((OE_PublicKey*)publicKey, buffer, bufferSize);
}

OE_Result OE_ECPublicKeyEqual(
    const OE_ECPublicKey* publicKey1,
    const OE_ECPublicKey* publicKey2,
    bool* equal)
{
    return _PublicKeyEqual(
        (OE_PublicKey*)publicKey1, (OE_PublicKey*)publicKey2, equal);
}
