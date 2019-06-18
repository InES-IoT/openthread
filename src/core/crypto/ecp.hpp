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

/**
 * @file
 *   This file includes definitions for performing elliptic key generation.
 */

#ifndef ECP_HPP_
#define ECP_HPP_

#include "openthread-core-config.h"

#include <stdint.h>
#include <stdlib.h>

#include <openthread/error.h>

namespace ot {
namespace Crypto {

/**
 * @addtogroup core-security
 *
 * @{
 *
 */

/**
 * This class implements elliptic curve key generation.
 *
 */
class Ecp
{
public:
    /**
     * This method generate a Elliptic Curve key pair.
     *
     * @param[in]       aPersonalSeed       An additional seed for the entropy. Can be NULL.
     * @param[in]       aPersonalSeedLengh  The length of the @p aPersonalSeed.
     * @param[out]      aPrivateKey         An output buffer where the private key should be stored.
     * @param[inout]    aPrivateKeyLength   The length of the @p aPrivateKey buffer.
     * @param[out]      aPublicKey          An output buffer where the private key should be stored.
     * @param[inout]    aPublicKeyLength    The length of the @p aPublicKey buffer.
     *
     * @retval  OT_ERROR_NONE       EC key pairs has been created successfully.
     *          OT_ERROR_NO_BUFS    Key buffers are too small or mbedtls heap too small.
     */
    static otError KeyPairGeneration(const uint8_t *aPersonalSeed,
                                     uint32_t       aPersonalSeedLength,
                                     uint8_t *      aPrivateKey,
                                     uint32_t *     aPrivateKeyLength,
                                     uint8_t *      aPublicKey,
                                     uint32_t *     aPublicKeyLength);
};

/**
 * @}
 *
 */

} // namespace Crypto
} // namespace ot

#endif // ECP_HPP_
