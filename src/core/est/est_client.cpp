/*
 *  Copyright (c) 2019, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include "est_client.hpp"

#include <string.h>

#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

#include "common/debug.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"

#include "openthread/entropy.h"
#include "openthread/random_crypto.h"

#if OPENTHREAD_ENABLE_EST_CLIENT

#include "../common/asn1.hpp"
#include "common/random.hpp"
#include "crypto/ecdsa.hpp"
#include "crypto/mbedtls.hpp"
#include "crypto/sha256.hpp"

/**
 * @file
 *   This file implements the EST client.
 */

namespace ot {
namespace Est {

#define EST_CERTIFICATE_BUFFER_SIZE 1024
#define EST_ATTRIBUTES_BUFFER_SIZE  256

#define EST_ASN1_OID_PKCS7_DATA \
    MBEDTLS_OID_PKCS "\x07"     \
                     "\x01" //[RFC3369]
#define EST_ASN1_OID_PKCS7_SIGNEDATA \
    MBEDTLS_OID_PKCS "\x07"          \
                     "\x02" //[RFC3369]

Client::Client(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mIsConnected(false)
    , mStarted(false)
    , mVerifyEstServerCertificate(false)
    , mIsEnroll(false)
    , mIsEnrolled(false)
    , mApplicationContext(NULL)
    , mConnectCallback(NULL)
    , mResponseCallback(NULL)
    , mCoapSecure(aInstance, true)
{
}

otError Client::Start(bool aVerifyPeer)
{
    otError mError = OT_ERROR_NONE;

    VerifyOrExit(mStarted == false, mError = OT_ERROR_ALREADY);

    mStarted                    = true;
    mVerifyEstServerCertificate = aVerifyPeer;

    mCoapSecure.SetSslAuthMode(mVerifyEstServerCertificate);
    mError = mCoapSecure.Start(kLocalPort);
    VerifyOrExit(mError);

exit:

    return mError;
}

void Client::Stop(void)
{
    mCoapSecure.Stop();
    mStarted = false;
}

otError Client::SetCertificate(const uint8_t *aX509Cert,
                               uint32_t       aX509Length,
                               const uint8_t *aPrivateKey,
                               uint32_t       aPrivateKeyLength)
{
    return mCoapSecure.SetCertificate(aX509Cert, aX509Length, aPrivateKey, aPrivateKeyLength);
    ;
}

otError Client::SetCaCertificateChain(const uint8_t *aX509CaCertificateChain, uint32_t aX509CaCertChainLength)
{
    return mCoapSecure.SetCaCertificateChain(aX509CaCertificateChain, aX509CaCertChainLength);
}

otError Client::Connect(const Ip6::SockAddr &     aSockAddr,
                        otHandleEstClientConnect  aConnectHandler,
                        otHandleEstClientResponse aResponseHandler,
                        void *                    aContext)
{
    mApplicationContext = aContext;
    mConnectCallback    = aConnectHandler;
    mResponseCallback   = aResponseHandler;
    mCoapSecure.Connect(aSockAddr, &Client::CoapSecureConnectedHandle, this);

    return OT_ERROR_NONE;
}

otError Client::CsrAttributesToString(uint8_t *      aData,
                                      const uint8_t *aDataEnd,
                                      char *         aString,
                                      uint32_t       aStringLength)
{
    otError  mError                   = OT_ERROR_NONE;
    uint8_t *mSetBegin                = NULL;
    size_t   mAttributeOidLength      = 0;
    size_t   mAttributeSetLength      = 0;
    size_t   mAttributeSequenceLength = 0;

    VerifyOrExit(otAsn1GetTag(&aData, aDataEnd, &mAttributeSequenceLength, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0,
                 mError = OT_ERROR_PARSE);

    while(aData < aDataEnd)
    {
        switch(*aData)
        {
        case MBEDTLS_ASN1_OID:
            VerifyOrExit(otAsn1GetTag(&aData, aDataEnd, &mAttributeOidLength, MBEDTLS_ASN1_OID) == 0,
                         mError = OT_ERROR_PARSE);

            if(memcmp(aData, MBEDTLS_OID_DIGEST_ALG_MD5, sizeof(MBEDTLS_OID_DIGEST_ALG_MD5) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("MESSAGE DIGEST: MD5\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "MESSAGE DIGEST: MD5\r\n");
            }
            else if(memcmp(aData, MBEDTLS_OID_DIGEST_ALG_SHA256, sizeof(MBEDTLS_OID_DIGEST_ALG_SHA256) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("MESSAGE DIGEST: SHA256\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "MESSAGE DIGEST: SHA256\r\n");
            }
            else if(memcmp(aData, MBEDTLS_OID_DIGEST_ALG_SHA384, sizeof(MBEDTLS_OID_DIGEST_ALG_SHA384) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("MESSAGE DIGEST: SHA384\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "MESSAGE DIGEST: SHA384\r\n");
            }
            else if(memcmp(aData, MBEDTLS_OID_DIGEST_ALG_SHA512, sizeof(MBEDTLS_OID_DIGEST_ALG_SHA512) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("MESSAGE DIGEST: SHA512\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "MESSAGE DIGEST: SHA512\r\n");
            }
            else if(memcmp(aData, MBEDTLS_OID_ECDSA_SHA256, sizeof(MBEDTLS_OID_ECDSA_SHA256) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("MESSAGE DIGEST: ECDSA with SHA256\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "MESSAGE DIGEST: ECDSA with SHA256\r\n");
            }
            else if(memcmp(aData, MBEDTLS_OID_ECDSA_SHA384, sizeof(MBEDTLS_OID_ECDSA_SHA384) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("MESSAGE DIGEST: ECDSA with SHA384\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "MESSAGE DIGEST: ECDSA with SHA384\r\n");
            }
            else if(memcmp(aData, MBEDTLS_OID_ECDSA_SHA512, sizeof(MBEDTLS_OID_ECDSA_SHA512) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("MESSAGE DIGEST: ECDSA with SHA512\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "MESSAGE DIGEST: ECDSA with SHA512\r\n");
            }
            else
            {
                VerifyOrExit(strlen(aString) + strlen("unknown attribute\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "unknown attribute\r\n");
            }
            aData += mAttributeOidLength;
            break;

        case MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE:
            VerifyOrExit(otAsn1GetTag(&aData, aDataEnd, &mAttributeSequenceLength, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0,
                         mError = OT_ERROR_PARSE);
            VerifyOrExit(otAsn1GetTag(&aData, aDataEnd, &mAttributeOidLength, MBEDTLS_ASN1_OID) == 0,
                         mError = OT_ERROR_PARSE);

            if(memcmp(aData, MBEDTLS_OID_EC_ALG_UNRESTRICTED, sizeof(MBEDTLS_OID_EC_ALG_UNRESTRICTED) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("KEY TYPE: EC\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "KEY TYPE: EC\r\n");

                aData += mAttributeOidLength;
                VerifyOrExit(otAsn1GetTag(&aData, aDataEnd, &mAttributeSetLength, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) == 0,
                             mError = OT_ERROR_PARSE);

                mSetBegin = aData;
                while(aData < (mSetBegin + mAttributeSetLength))
                {
                    VerifyOrExit(otAsn1GetTag(&aData, aDataEnd, &mAttributeOidLength, MBEDTLS_ASN1_OID) == 0,
                                 mError = OT_ERROR_PARSE);

                    if(memcmp(aData, MBEDTLS_OID_EC_GRP_SECP192R1, sizeof(MBEDTLS_OID_EC_GRP_SECP192R1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: SECP192R1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: SECP192R1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_SECP224R1, sizeof(MBEDTLS_OID_EC_GRP_SECP224R1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: SECP224R1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: SECP224R1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_SECP256R1, sizeof(MBEDTLS_OID_EC_GRP_SECP256R1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: SECP256R1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: SECP256R1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_SECP384R1, sizeof(MBEDTLS_OID_EC_GRP_SECP384R1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: SECP384R1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: SECP384R1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_SECP521R1, sizeof(MBEDTLS_OID_EC_GRP_SECP521R1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: SECP521R1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: SECP521R1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_SECP192K1, sizeof(MBEDTLS_OID_EC_GRP_SECP192K1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: SECP192K1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: SECP192K1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_SECP224K1, sizeof(MBEDTLS_OID_EC_GRP_SECP224K1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: SECP224K1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: SECP224K1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_SECP256K1, sizeof(MBEDTLS_OID_EC_GRP_SECP256K1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: SECP256K1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: SECP256K1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_BP256R1, sizeof(MBEDTLS_OID_EC_GRP_BP256R1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: BP256R1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: BP256R1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_BP384R1, sizeof(MBEDTLS_OID_EC_GRP_BP384R1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: BP384R1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: BP384R1\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EC_GRP_BP512R1, sizeof(MBEDTLS_OID_EC_GRP_BP512R1) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EC GROUP: BP512R1\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EC GROUP: BP512R1\r\n");
                    }
                    else
                    {
                        VerifyOrExit(strlen(aString) + strlen("    unknown attribute\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    unknown attribute\r\n");
                    }
                    aData += mAttributeOidLength;
                }
            }
            else if(memcmp(aData, MBEDTLS_OID_PKCS9_CSR_EXT_REQ, sizeof(MBEDTLS_OID_PKCS9_CSR_EXT_REQ) - 1) == 0)
            {
                VerifyOrExit(strlen(aString) + strlen("CSR EXTENSION REQUEST\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "CSR EXTENSION REQUEST\r\n");

                aData += mAttributeOidLength;
                VerifyOrExit(otAsn1GetTag(&aData, aDataEnd, &mAttributeSetLength, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) == 0,
                             mError = OT_ERROR_PARSE);

                mSetBegin = aData;
                while(aData < (mSetBegin + mAttributeSetLength))
                {
                    VerifyOrExit(otAsn1GetTag(&aData, aDataEnd, &mAttributeOidLength, MBEDTLS_ASN1_OID) == 0,
                                 mError = OT_ERROR_PARSE);

                    if(memcmp(aData, MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER, sizeof(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    AUTHORITY KEY IDENTIFIER\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    AUTHORITY KEY IDENTIFIER\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER, sizeof(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    SUBJECT KEY IDENTIFIER\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    SUBJECT KEY IDENTIFIER\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_KEY_USAGE, sizeof(MBEDTLS_OID_KEY_USAGE) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    KEY USAGE\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    KEY USAGE\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_CERTIFICATE_POLICIES, sizeof(MBEDTLS_OID_CERTIFICATE_POLICIES) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    CERTIFICATE POLICIES\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    CERTIFICATE POLICIES\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_POLICY_MAPPINGS, sizeof(MBEDTLS_OID_POLICY_MAPPINGS) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    POLICY MAPPINGS\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    POLICY MAPPINGS\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_SUBJECT_ALT_NAME, sizeof(MBEDTLS_OID_SUBJECT_ALT_NAME) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    SUBJECT ALT NAME\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    SUBJECT ALT NAME\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_ISSUER_ALT_NAME, sizeof(MBEDTLS_OID_ISSUER_ALT_NAME) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    ISSUER ALT NAME\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    ISSUER ALT NAME\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_SUBJECT_DIRECTORY_ATTRS, sizeof(MBEDTLS_OID_SUBJECT_DIRECTORY_ATTRS) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    SUBJECT DIRECTORY ATTRS\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    SUBJECT DIRECTORY ATTRS\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_BASIC_CONSTRAINTS, sizeof(MBEDTLS_OID_BASIC_CONSTRAINTS) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    BASIC CONSTRAINTS\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    BASIC CONSTRAINTS\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_NAME_CONSTRAINTS, sizeof(MBEDTLS_OID_NAME_CONSTRAINTS) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    NAME CONSTRAINTS\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    NAME CONSTRAINTS\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_POLICY_CONSTRAINTS, sizeof(MBEDTLS_OID_POLICY_CONSTRAINTS) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    POLICY CONSTRAINTS\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    POLICY CONSTRAINTS\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_EXTENDED_KEY_USAGE, sizeof(MBEDTLS_OID_EXTENDED_KEY_USAGE) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    EXTENDED KEY USAGE\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    EXTENDED KEY USAGE\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_CRL_DISTRIBUTION_POINTS, sizeof(MBEDTLS_OID_CRL_DISTRIBUTION_POINTS) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    CRL DISTRIBUTION POINTS\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    CRL DISTRIBUTION POINTS\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_INIHIBIT_ANYPOLICY, sizeof(MBEDTLS_OID_INIHIBIT_ANYPOLICY) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    INIHIBIT ANYPOLICY\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    INIHIBIT ANYPOLICY\r\n");
                    }
                    else if(memcmp(aData, MBEDTLS_OID_FRESHEST_CRL, sizeof(MBEDTLS_OID_FRESHEST_CRL) - 1) == 0)
                    {
                        VerifyOrExit(strlen(aString) + strlen("    FRESHEST CRL\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    FRESHEST CRL\r\n");
                    }
                    else
                    {
                        VerifyOrExit(strlen(aString) + strlen("    unknown attribute\r\n") < aStringLength,
                                     mError = OT_ERROR_NO_BUFS);

                        strcat(aString, "    unknown attribute\r\n");
                    }
                    aData += mAttributeOidLength;
                }
            }
            else
            {
                VerifyOrExit(strlen(aString) + strlen("unknown attribute\r\n") < aStringLength,
                             mError = OT_ERROR_NO_BUFS);

                strcat(aString, "unknown attribute\r\n");

                aData += mAttributeSequenceLength;
            }
            break;

        default:
            VerifyOrExit(strlen(aString) + strlen("unknown attribute\r\n") < aStringLength,
                         mError = OT_ERROR_NO_BUFS);

            strcat(aString, "unknown attribute\r\n");

            aData++;
            VerifyOrExit(otAsn1GetLength(&aData, aDataEnd, &mAttributeSequenceLength) == 0,
                         mError = OT_ERROR_PARSE);
            aData += mAttributeSequenceLength;
            break;
        }
    }

exit:

return mError;
}

void Client::Disconnect(void)
{
    mCoapSecure.Disconnect();
}

bool Client::IsConnected(void)
{
    return mIsConnected;
}

otError Client::SimpleEnroll(const uint8_t *aPrivateKey,
                             uint32_t       aPrivateLeyLength,
                             otMdType       aMdType,
                             uint8_t        aKeyUsageFlags,
                             uint8_t *      aX509Extensions,
                             uint32_t       aX509ExtensionsLength)
{
    otError        mError                               = OT_ERROR_NONE;
    uint8_t        mBuffer[EST_CERTIFICATE_BUFFER_SIZE] = {0};
    size_t         mBufferLength                        = EST_CERTIFICATE_BUFFER_SIZE;
    uint8_t *      mBufferPointer                       = NULL;
    Coap::Message *mCoapMessage                         = NULL;

    VerifyOrExit(mIsConnected, mError = OT_ERROR_INVALID_STATE);

    SuccessOrExit(mError = Client::WriteCsr(aPrivateKey,
                                            aPrivateLeyLength,
                                            aMdType,
                                            aKeyUsageFlags,
                                            aX509Extensions,
                                            aX509ExtensionsLength,
                                            mBuffer,
                                            &mBufferLength));

    // The CSR is written at the end of the buffer, therefore the pointer is set to the begin of the CSR
    mBufferPointer = mBuffer + (EST_CERTIFICATE_BUFFER_SIZE - mBufferLength);

    // Send CSR
    VerifyOrExit((mCoapMessage = mCoapSecure.NewMessage(NULL)) != NULL, mError = OT_ERROR_NO_BUFS);

    SuccessOrExit(mError = mCoapMessage->Init(OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_POST, OT_EST_COAPS_SHORT_URI_SIMPLE_ENROLL));

    SuccessOrExit(mError = mCoapMessage->AppendContentFormatOption(OT_COAP_OPTION_CONTENT_FORMAT_PKCS10));

    SuccessOrExit(mError = mCoapMessage->SetPayloadMarker());

    SuccessOrExit(mError = mCoapMessage->Append(mBufferPointer, mBufferLength));

    mCoapSecure.SendMessage(*mCoapMessage, &Client::SimpleEnrollResponseHandler, this);

    mIsEnroll = true;

exit:

    return mError;
}

otError Client::SimpleReEnroll(const uint8_t *aPrivateKey,
                               uint32_t       aPrivateLeyLength,
                               otMdType       aMdType,
                               uint8_t        aKeyUsageFlags,
                               uint8_t *      aX509Extensions,
                               uint32_t       aX509ExtensionsLength)
{
    otError        mError                               = OT_ERROR_NONE;
    uint8_t        mBuffer[EST_CERTIFICATE_BUFFER_SIZE] = {0};
    size_t         mBufferLength                        = EST_CERTIFICATE_BUFFER_SIZE;
    uint8_t *      mBufferPointer                       = NULL;
    Coap::Message *mCoapMessage                         = NULL;

    VerifyOrExit(mIsConnected && mIsEnrolled, mError = OT_ERROR_INVALID_STATE);

    SuccessOrExit(mError = Client::WriteCsr(aPrivateKey,
                                            aPrivateLeyLength,
                                            aMdType,
                                            aKeyUsageFlags,
                                            aX509Extensions,
                                            aX509ExtensionsLength,
                                            mBuffer,
                                            &mBufferLength));

    // The CSR is written at the end of the buffer, therefore the pointer is set to the begin of the CSR
    mBufferPointer = mBuffer + (EST_CERTIFICATE_BUFFER_SIZE - mBufferLength);

    // Send CSR
    VerifyOrExit((mCoapMessage = mCoapSecure.NewMessage(NULL)) != NULL, mError = OT_ERROR_NO_BUFS);

    SuccessOrExit(mError = mCoapMessage->Init(OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_POST,
                                             OT_EST_COAPS_SHORT_URI_SIMPLE_REENROLL));

    SuccessOrExit(mError = mCoapMessage->AppendContentFormatOption(OT_COAP_OPTION_CONTENT_FORMAT_PKCS10));

    SuccessOrExit(mError = mCoapMessage->SetPayloadMarker());

    SuccessOrExit(mError = mCoapMessage->Append(mBufferPointer, mBufferLength));

    mCoapSecure.SendMessage(*mCoapMessage, &Client::SimpleEnrollResponseHandler, this);

    mIsEnroll = false;

exit:

    return mError;
}

otError Client::GetCsrAttributes(void)
{
    otError        mError       = OT_ERROR_NONE;
    Coap::Message *mCoapMessage = NULL;

    VerifyOrExit(mIsConnected, mError = OT_ERROR_INVALID_STATE);

    VerifyOrExit((mCoapMessage = mCoapSecure.NewMessage(NULL)) != NULL, mError = OT_ERROR_NO_BUFS);

    SuccessOrExit(mError = mCoapMessage->Init(OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_GET,
                                              OT_EST_COAPS_SHORT_URI_CSR_ATTRS));

    mCoapSecure.SendMessage(*mCoapMessage, &Client::GetCsrAttributesResponseHandler, this);
exit:

    return mError;
}

otError Client::GetServerGeneratedKeys(void)
{
    otError mError = OT_ERROR_NOT_IMPLEMENTED;

    VerifyOrExit(mIsConnected, mError = OT_ERROR_INVALID_STATE);

exit:

    return mError;
}

otError Client::GetCaCertificates(void)
{
    otError        mError       = OT_ERROR_NONE;
    Coap::Message *mCoapMessage = NULL;

    VerifyOrExit(mIsConnected, mError = OT_ERROR_INVALID_STATE);

    VerifyOrExit((mCoapMessage = mCoapSecure.NewMessage(NULL)) != NULL, mError = OT_ERROR_NO_BUFS);

    SuccessOrExit(mError = mCoapMessage->Init(OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_GET,
                                              OT_EST_COAPS_SHORT_URI_CA_CERTS));

    mCoapSecure.SendMessage(*mCoapMessage, &Client::GetCaCertificatesResponseHandler, this);

exit:

    return mError;
}

void Client::CoapSecureConnectedHandle(bool aConnected, void *aContext)
{
    return static_cast<Client *>(aContext)->CoapSecureConnectedHandle(aConnected);
}

void Client::CoapSecureConnectedHandle(bool aConnected)
{
    mIsConnected = aConnected;

    if (mConnectCallback != NULL)
    {
        mConnectCallback(aConnected, mApplicationContext);
    }
}

otError Client::CmsReadSignedData(uint8_t * aMessage,
                                  uint32_t  aMessageLength,
                                  uint8_t **aPayload,
                                  uint32_t *aPayloadLength)
{
    otError  mError          = OT_ERROR_NONE;
    uint8_t *mMessagePointer = NULL;
    uint8_t *mMessageEnd     = NULL;
    size_t   mSequenceLength = 0;

    mMessagePointer = aMessage;
    mMessageEnd     = aMessage + aMessageLength;

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0,
                 mError = OT_ERROR_SECURITY);

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength, MBEDTLS_ASN1_OID) == 0,
                 mError = OT_ERROR_SECURITY);

    VerifyOrExit(memcmp(mMessagePointer, EST_ASN1_OID_PKCS7_SIGNEDATA, mSequenceLength) == 0,
                 mError = OT_ERROR_SECURITY);

    mMessagePointer += mSequenceLength;

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) == 0,
                 mError = OT_ERROR_SECURITY);

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0,
                 mError = OT_ERROR_SECURITY);

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength, MBEDTLS_ASN1_INTEGER) == 0,
                 mError = OT_ERROR_SECURITY);

    mMessagePointer += mSequenceLength;

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) == 0,
                 mError = OT_ERROR_SECURITY);

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0,
                 mError = OT_ERROR_SECURITY);

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength, MBEDTLS_ASN1_OID) == 0,
                 mError = OT_ERROR_SECURITY);

    VerifyOrExit(memcmp(mMessagePointer, EST_ASN1_OID_PKCS7_DATA, mSequenceLength) == 0, mError = OT_ERROR_SECURITY);

    mMessagePointer += mSequenceLength;

    VerifyOrExit(otAsn1GetTag(&mMessagePointer, mMessageEnd, &mSequenceLength,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) == 0,
                 mError = OT_ERROR_SECURITY);

    *aPayload       = mMessagePointer;
    *aPayloadLength = mSequenceLength;

exit:
    return mError;
}

otError Client::WriteCsr(const uint8_t *aPrivateKey,
                         size_t         aPrivateLeyLength,
                         otMdType       aMdType,
                         uint8_t        aKeyUsageFlags,
                         uint8_t *      aX509Extensions,
                         uint32_t       aX509ExtensionsLength,
                         uint8_t *      aOutput,
                         size_t *       aOutputLength)
{
    otError               mError                 = OT_ERROR_NONE;
    mbedtls_x509write_csr csr;
    mbedtls_pk_context    pkCtx;
    uint8_t               nsCertType             = 0;
    uint8_t *             mX509ExtensionsPointer = aX509Extensions;
    uint8_t *             mOidPointer            = NULL;
    uint8_t *             mValuePointer          = NULL;
    const uint8_t *       mX509ExtensionsEnd     = aX509Extensions + aX509ExtensionsLength;
    size_t                mOidLength             = 0;
    size_t                mValueLength           = 0;

    mbedtls_x509write_csr_init(&csr);
    mbedtls_pk_init(&pkCtx);

    // Parse key pair
    VerifyOrExit(mbedtls_pk_parse_key(&pkCtx, aPrivateKey, aPrivateLeyLength, NULL, 0) == 0,
                 mError = OT_ERROR_INVALID_ARGS);

    // Create PKCS#10
    mbedtls_x509write_csr_set_md_alg(&csr, (mbedtls_md_type_t)aMdType);

    VerifyOrExit(mbedtls_x509write_csr_set_key_usage(&csr, aKeyUsageFlags) == 0, mError = OT_ERROR_INVALID_ARGS);

    nsCertType |= MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT;
    VerifyOrExit(mbedtls_x509write_csr_set_ns_cert_type(&csr, nsCertType) == 0, mError = OT_ERROR_FAILED);

    mbedtls_x509write_csr_set_key(&csr, &pkCtx);

    // Set X.509 extensions
    if(aX509Extensions != NULL)
    {
        otAsn1GetTag(&mX509ExtensionsPointer, mX509ExtensionsEnd, NULL, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);

        while(mX509ExtensionsPointer < mX509ExtensionsEnd)
        {
            VerifyOrExit(otAsn1GetTag(&mX509ExtensionsPointer, mX509ExtensionsEnd, &mOidLength, MBEDTLS_ASN1_OID) == 0,
                         mError = OT_ERROR_INVALID_ARGS);

            mOidPointer = mX509ExtensionsPointer;
            mX509ExtensionsPointer += mOidLength;
            mValuePointer = mX509ExtensionsPointer;

            VerifyOrExit(otAsn1GetLength(&mX509ExtensionsPointer, mX509ExtensionsEnd, &mValueLength) == 0,
                         mError = OT_ERROR_INVALID_ARGS);

            mValueLength += mX509ExtensionsPointer - mValuePointer;

            VerifyOrExit(mbedtls_x509write_csr_set_extension(&csr, (char*)mOidPointer,
                                                             mOidLength, mValuePointer, mValueLength),
                         mError = OT_ERROR_INVALID_ARGS);

            mX509ExtensionsPointer = mValuePointer + mValueLength;
        }
    }

    // Write CSR in DER format
    VerifyOrExit((*aOutputLength = mbedtls_x509write_csr_der(&csr, aOutput, *aOutputLength, mbedtls_ctr_drbg_random,
                                                             Random::Crypto::MbedTlsContextGet())) > 0,
                 mError = OT_ERROR_NO_BUFS);

exit:
    mbedtls_x509write_csr_free(&csr);
    mbedtls_pk_free(&pkCtx);

    return mError;
}

void Client::SimpleEnrollResponseHandler(void *               aContext,
                                         otMessage *          aMessage,
                                         const otMessageInfo *aMessageInfo,
                                         otError              aResult)
{
    return static_cast<Client *>(aContext)->SimpleEnrollResponseHandler(aMessage, aMessageInfo, aResult);
}

void Client::SimpleEnrollResponseHandler(otMessage *aMessage, const otMessageInfo *aMessageInfo, otError aResult)
{
    OT_UNUSED_VARIABLE(aMessageInfo);

    otCoapCode       mCoapCode                                 = otCoapMessageGetCode(aMessage);
    otEstType        mType                                     = OT_EST_TYPE_NONE;
    uint8_t          mMessage[EST_CERTIFICATE_BUFFER_SIZE + 1] = {0};
    uint32_t         mMessageLength                            = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    uint8_t *        mPayload                                  = NULL;
    uint32_t         mPayloadLength                            = 0;
    mbedtls_x509_crt mCertificate;

    mbedtls_x509_crt_init(&mCertificate);

    VerifyOrExit(aResult == OT_ERROR_NONE, mMessageLength = 0);

    switch (mCoapCode)
    {
    case OT_COAP_CODE_CREATED:
        // Check if message is too long for buffer
        VerifyOrExit(mMessageLength <= sizeof(mMessage), aResult = OT_ERROR_NO_BUFS;);

        // Parse message
        mMessage[mMessageLength] = '\0';
        otMessageRead(aMessage, otMessageGetOffset(aMessage), mMessage, mMessageLength);

        SuccessOrExit(aResult = Client::CmsReadSignedData(mMessage, mMessageLength, &mPayload, &mPayloadLength));

        // Check if payload is a valid x509 certificate
        VerifyOrExit(mbedtls_x509_crt_parse_der(&mCertificate, (unsigned char *)mPayload, mPayloadLength) == 0,
                     mType = OT_EST_TYPE_INVALID_CERT);

        mIsEnrolled = true;

        if (mIsEnroll)
        {
            mType = OT_EST_TYPE_SIMPLE_ENROLL;
        }
        else
        {
            mType = OT_EST_TYPE_SIMPLE_REENROLL;
        }
        break;

    default:
        aResult        = OT_ERROR_FAILED;
        mPayloadLength = 0;
        break;
    }

exit:
    mbedtls_x509_crt_free(&mCertificate);

    mResponseCallback(aResult, mType, mPayload, mPayloadLength, mApplicationContext);
}

void Client::GetCaCertificatesResponseHandler(void *               aContext,
                                              otMessage *          aMessage,
                                              const otMessageInfo *aMessageInfo,
                                              otError              aResult)
{
    return static_cast<Client *>(aContext)->GetCaCertificatesResponseHandler(aMessage,
                                                                             aMessageInfo,
                                                                             aResult);
}

void Client::GetCaCertificatesResponseHandler(otMessage *          aMessage,
                                              const otMessageInfo *aMessageInfo,
                                              otError              aResult)
{
    OT_UNUSED_VARIABLE(aMessageInfo);

    otCoapCode       mCoapCode                                 = otCoapMessageGetCode(aMessage);
    otEstType        mType                                     = OT_EST_TYPE_NONE;
    uint8_t          mMessage[EST_CERTIFICATE_BUFFER_SIZE + 1] = {0};
    uint32_t         mMessageLength                            = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    uint8_t *        mPayload                                  = NULL;
    uint32_t         mPayloadLength                            = 0;
    mbedtls_x509_crt mCertificate;

    mbedtls_x509_crt_init(&mCertificate);

    switch (mCoapCode)
    {
    case OT_COAP_CODE_CONTENT:
        // Check if message is too long for buffer
        VerifyOrExit(mMessageLength <= sizeof(mMessage), aResult = OT_ERROR_NO_BUFS;);

        // Parse message
        mMessage[mMessageLength] = '\0';
        otMessageRead(aMessage, otMessageGetOffset(aMessage), mMessage, mMessageLength);

        SuccessOrExit(aResult = Client::CmsReadSignedData(mMessage, mMessageLength, &mPayload, &mPayloadLength));

        // Check if payload is a valid x509 certificate
        VerifyOrExit(mbedtls_x509_crt_parse_der(&mCertificate, (unsigned char *)mPayload, mPayloadLength) == 0,
                     mType = OT_EST_TYPE_INVALID_CERT);

        mType = OT_EST_TYPE_CA_CERTS;
        break;

    default:
        aResult        = OT_ERROR_FAILED;
        mPayloadLength = 0;
        break;
    }

exit:
    mbedtls_x509_crt_free(&mCertificate);

    mResponseCallback(aResult, mType, mPayload, mPayloadLength, mApplicationContext);
}

void Client::GetCsrAttributesResponseHandler(void *               aContext,
                                             otMessage *          aMessage,
                                             const otMessageInfo *aMessageInfo,
                                             otError              aResult)
{
    return static_cast<Client *>(aContext)->GetCsrAttributesResponseHandler(aMessage,
                                                                            aMessageInfo,
                                                                            aResult);
}

void Client::GetCsrAttributesResponseHandler(otMessage *          aMessage,
                                             const otMessageInfo *aMessageInfo,
                                             otError              aResult)
{
    OT_UNUSED_VARIABLE(aMessageInfo);

    otCoapCode       mCoapCode                                = otCoapMessageGetCode(aMessage);
    otEstType        mType                                    = OT_EST_TYPE_NONE;
    uint8_t          mMessage[EST_ATTRIBUTES_BUFFER_SIZE + 1] = {0};
    uint32_t         mMessageLength                           = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);

    switch (mCoapCode)
    {
    case OT_COAP_CODE_CONTENT:
        // Check if message is too long for buffer
        VerifyOrExit(mMessageLength <= sizeof(mMessage), aResult = OT_ERROR_NO_BUFS;);

        // Parse message
        mMessage[mMessageLength] = '\0';
        otMessageRead(aMessage, otMessageGetOffset(aMessage), mMessage, mMessageLength);

        mType = OT_EST_TYPE_CSR_ATTR;
        break;

    default:
        aResult        = OT_ERROR_FAILED;
        mMessageLength = 0;
        break;
    }

exit:

    mResponseCallback(aResult, mType, mMessage, mMessageLength, mApplicationContext);
}

} // namespace Est
} // namespace ot

#endif // OPENTHREAD_ENABLE_EST_CLIENT
