/*
 *  Copyright (c) 2016, The OpenThread Authors.
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
 *   This file includes definitions for generating and processing CoAP messages.
 */

#ifndef COAP_HEADER_HPP_
#define COAP_HEADER_HPP_

#include "openthread-core-config.h"

#include <openthread/coap.h>

#include "common/code_utils.hpp"
#include "common/encoding.hpp"
#include "common/message.hpp"
#include "utils/static_assert.hpp"

namespace ot {

/**
 * @namespace ot::Coap
 * @brief
 *   This namespace includes definitions for CoAP.
 *
 */
namespace Coap {

using ot::Encoding::BigEndian::HostSwap16;

/**
 * @addtogroup core-coap
 *
 * @brief
 *   This module includes definitions for CoAP.
 *
 * @{
 *
 */

class OptionIterator;

/**
 * This class implements CoAP message generation and parsing.
 *
 */
class Message : public ot::Message
{
    friend class OptionIterator;

public:
    enum
    {
        kVersion1           = 1,   ///< Version 1
        kMinHeaderLength    = 4,   ///< Minimum header length
        kMaxHeaderLength    = 512, ///< Maximum header length
        kDefaultTokenLength = 2,   ///< Default token length
        kTypeOffset         = 4,   ///< The type offset in the first byte of a CoAP header
    };

    /**
     * CoAP Type values.
     *
     */
    typedef otCoapType Type;

    /**
     * CoAP Code values.
     *
     */
    typedef otCoapCode Code;

    /**
     * CoAP Block1/Block2 Types
     *
     */
    enum BlockType
    {
        kBlockType1 = 1,
        kBlockType2 = 2,
    };

    enum
    {
        kBlockSzxBase = 4,
    };

    /**
     * This method initializes the CoAP header.
     *
     */
    void Init(void);

    /**
     * This method initializes the CoAP header with specific Type and Code.
     *
     * @param[in]  aType  The Type value.
     * @param[in]  aCode  The Code value.
     *
     */
    void Init(Type aType, Code aCode);

    /**
     * This method initializes the CoAP header with specific Type and Code.
     *
     * @param[in]  aType              The Type value.
     * @param[in]  aCode              The Code value.
     * @param[in]  aUriPath           A pointer to a NULL-terminated string.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     *
     */
    otError Init(Type aType, Code aCode, const char *aUriPath);

    /**
     * This method writes header to the message. This must be called before sending the message.
     *
     */
    void Finish(void);

    /**
     * This method returns the Version value.
     *
     * @returns The Version value.
     *
     */
    uint8_t GetVersion(void) const
    {
        return (GetHelpData().mHeader.mVersionTypeToken & kVersionMask) >> kVersionOffset;
    }

    /**
     * This method sets the Version value.
     *
     * @param[in]  aVersion  The Version value.
     *
     */
    void SetVersion(uint8_t aVersion)
    {
        GetHelpData().mHeader.mVersionTypeToken &= ~kVersionMask;
        GetHelpData().mHeader.mVersionTypeToken |= aVersion << kVersionOffset;
    }

    /**
     * This method returns the Type value.
     *
     * @returns The Type value.
     *
     */
    Type GetType(void) const { return static_cast<Type>(GetHelpData().mHeader.mVersionTypeToken & kTypeMask); }

    /**
     * This method sets the Type value.
     *
     * @param[in]  aType  The Type value.
     *
     */
    void SetType(Type aType)
    {
        GetHelpData().mHeader.mVersionTypeToken &= ~kTypeMask;
        GetHelpData().mHeader.mVersionTypeToken |= aType;
    }

    /**
     * This method returns the Code value.
     *
     * @returns The Code value.
     *
     */
    Code GetCode(void) const { return static_cast<Code>(GetHelpData().mHeader.mCode); }

    /**
     * This method sets the Code value.
     *
     * @param[in]  aCode  The Code value.
     *
     */
    void SetCode(Code aCode) { GetHelpData().mHeader.mCode = static_cast<uint8_t>(aCode); }

#if OPENTHREAD_CONFIG_COAP_API_ENABLE
    /**
     * This method returns the CoAP Code as human readable string.
     *
     * @ returns The CoAP Code as string.
     *
     */
    const char *CodeToString(void) const;
#endif // OPENTHREAD_CONFIG_COAP_API_ENABLE

    /**
     * This method returns the Message ID value.
     *
     * @returns The Message ID value.
     *
     */
    uint16_t GetMessageId(void) const { return HostSwap16(GetHelpData().mHeader.mMessageId); }

    /**
     * This method sets the Message ID value.
     *
     * @param[in]  aMessageId  The Message ID value.
     *
     */
    void SetMessageId(uint16_t aMessageId) { GetHelpData().mHeader.mMessageId = HostSwap16(aMessageId); }

    /**
     * This method returns the Token length.
     *
     * @returns The Token length.
     *
     */
    uint8_t GetTokenLength(void) const
    {
        return (GetHelpData().mHeader.mVersionTypeToken & kTokenLengthMask) >> kTokenLengthOffset;
    }

    /**
     * This method returns a pointer to the Token value.
     *
     * @returns A pointer to the Token value.
     *
     */
    const uint8_t *GetToken(void) const { return GetHelpData().mHeader.mToken; }

    /**
     * This method sets the Token value and length.
     *
     * @param[in]  aToken        A pointer to the Token value.
     * @param[in]  aTokenLength  The Length of @p aToken.
     *
     * @retval OT_ERROR_NONE     Successfully set the token value.
     * @retval OT_ERROR_NO_BUFS  Insufficient message buffers available to set the token value.
     *
     */
    otError SetToken(const uint8_t *aToken, uint8_t aTokenLength);

    /**
     * This method sets the Token length and randomizes its value.
     *
     * @param[in]  aTokenLength  The Length of a Token to set.
     *
     * @retval OT_ERROR_NONE     Successfully set the token value.
     * @retval OT_ERROR_NO_BUFS  Insufficient message buffers available to set the token value.
     *
     */
    otError SetToken(uint8_t aTokenLength);

    /**
     * This method checks if Tokens in two CoAP headers are equal.
     *
     * @param[in]  aMessage  A header to compare.
     *
     * @retval TRUE   If two Tokens are equal.
     * @retval FALSE  If Tokens differ in length or value.
     *
     */
    bool IsTokenEqual(const Message &aMessage) const
    {
        return ((this->GetTokenLength() == aMessage.GetTokenLength()) &&
                (memcmp(this->GetToken(), aMessage.GetToken(), this->GetTokenLength()) == 0));
    }

    /**
     * This method appends a CoAP option.
     *
     * @param[in]  aOption  The CoAP Option.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     *
     */
    otError AppendOption(uint16_t aNumber, uint16_t aLength, const void *aValue);

    /**
     * This method appends an unsigned integer CoAP option as specified in
     * https://tools.ietf.org/html/rfc7252#section-3.2
     *
     * @param[in]  aNumber  The CoAP Option number.
     * @param[in]  aValue   The CoAP Option unsigned integer value.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     *
     */
    otError AppendUintOption(uint16_t aNumber, uint32_t aValue);

    /**
     * This method appends a string CoAP option.
     *
     * @param[in]  aNumber  The CoAP Option number.
     * @param[in]  aValue   The CoAP Option string value.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     *
     */
    otError AppendStringOption(uint16_t aNumber, const char *aValue);

    /**
     * This method appends an Observe option.
     *
     * @param[in]  aObserve  Observe field value.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     */
    otError AppendObserveOption(uint32_t aObserve);

    /**
     * This method appends a Uri-Path option.
     *
     * @param[in]  aUriPath           A pointer to a NULL-terminated string.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     *
     */
    otError AppendUriPathOptions(const char *aUriPath);

    /**
     * This method appends a Block option
     *
     * @param[in]  aType              Type of block option, 1 or 2.
     * @param[in]  aNum               Current block number.
     * @param[in]  aMore              Boolean to indicate more blocks are to be sent.
     * @param[in]  aSize              Maximum block size.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     *
     */
    otError AppendBlockOption(BlockType aType, uint32_t aNum, bool aMore, otCoapBlockSize aSize);

    /**
     * This method appends a Proxy-Uri option.
     *
     * @param[in]  aProxyUri          A pointer to a NULL-terminated string.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     *
     */
    otError AppendProxyUriOption(const char *aProxyUri);

    /**
     * This method appends a Content-Format option.
     *
     * @param[in]  aContentFormat  The Content Format value.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     *
     */
    otError AppendContentFormatOption(otCoapOptionContentFormat aContentFormat);

    /**
     * This method appends a Max-Age option.
     *
     * @param[in]  aMaxAge  The Max-Age value.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     */
    otError AppendMaxAgeOption(uint32_t aMaxAge);

    /**
     * This method appends a single Uri-Query option.
     *
     * @param[in]  aUriQuery  A pointer to NULL-terminated string, which should contain a single key=value pair.
     *
     * @retval OT_ERROR_NONE          Successfully appended the option.
     * @retval OT_ERROR_INVALID_ARGS  The option type is not equal or greater than the last option type.
     * @retval OT_ERROR_NO_BUFS       The option length exceeds the buffer size.
     */
    otError AppendUriQueryOption(const char *aUriQuery);

    /**
     * This function reads the information contained in a Block1 or Block2 option.
     *
     * @param[in]   aBlockType      Block1 or Block2 option value.
     * @param[out]  aBlockNumber    The relative number of the block within a sequence of blocks.
     * @param[out]  aMoreBlocks     More blocks are following.
     * @param[out]  aBlockSize      One of the block lengths listed in
     *                              otCoapOptionBlockSize above.
     *
     * @retval  OT_ERROR_NONE           The option has been found and is valid.
     * @retval  OT_ERROR_NOT_FOUND      The option has not been found.
     * @retval  OT_ERROR_INVALID_ARGS   The option is invalid.
     */
    otError ReadBlockOptionValues(otCoapOptionType       aBlockType,
                                  uint32_t *             aBlockNumber,
                                  bool *                 aMoreBlocks,
                                  otCoapOptionBlockSize *aBlockSize);

#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    /**
     * This function reads the information contained in a Block1 or Block2 option and set it in
     * the HelpData of the message.
     *
     * @param[in]   aBlockType  Block1 or Block2 option value.
     *
     * @retval  OT_ERROR_NONE           The option has been found and is valid.
     * @retval  OT_ERROR_NOT_FOUND      The option has not been found.
     * @retval  OT_ERROR_INVALID_ARGS   The option is invalid.
     */
    otError ReadBlockOptionValues(otCoapOptionType aBlockType);

    /**
     * This method returns the current header length of a message.
     *
     * @returns The length of the message header.
     *
     */
    uint16_t GetHeaderLength(void) const { return GetHelpData().mHeaderLength; }

    /**
     * This method returns the block number of a CoAP block-wise transfer message.
     *
     * @returns The block number.
     *
     */
    uint32_t GetBlockWiseBlockNumber(void) { return GetHelpData().mBlockWiseData.mBlockNumber; }

    /**
     * This method checks if the More Blocks flag is set.
     *
     * @retval TRUE   More Blocks flag is set.
     * @retval FALSE  More Blocks flag is not set.
     *
     */
    bool IsMoreBlocksFlagSet(void) { return GetHelpData().mBlockWiseData.mMoreBlocks; }

    /**
     * This method returns the block size of a CoAP block-wise transfer message.
     *
     * @returns The block size.
     *
     */
    otCoapOptionBlockSize GetBlockWiseBlockSize(void) { return GetHelpData().mBlockWiseData.mBlockSize; }
#endif

    /**
     * This function reads and reassembles the URI path string and fills it into @p aUriPath.
     *
     * @retval  OT_ERROR_NONE       URI path string has been reassembled.
     * @retval  OT_ERROR_NO_BUFS    URI path string is too long.
     */
    otError GetUriPath(char *aUriPath);

    /**
     * This method adds Payload Marker indicating beginning of the payload to the CoAP header.
     *
     * It also set offset to the start of payload.
     *
     * @retval OT_ERROR_NONE     Payload Marker successfully added.
     * @retval OT_ERROR_NO_BUFS  Message Payload Marker exceeds the buffer size.
     *
     */
    otError SetPayloadMarker(void);

    /**
     * This method returns the offset of the first CoAP option.
     *
     * @returns The offset of the first CoAP option.
     *
     */
    uint16_t GetOptionStart(void) const { return kMinHeaderLength + GetTokenLength(); }

    /**
     * This method parses CoAP header and moves offset end of CoAP header.
     *
     * @retval  OT_ERROR_NONE   Successfully parsed CoAP header from the message.
     * @retval  OT_ERROR_PARSE  Failed to parse the CoAP header.
     *
     */
    otError ParseHeader(void);

    /**
     * This method sets a default response header based on request header.
     *
     * @param[in]  aRequest  The request message.
     *
     * @retval OT_ERROR_NONE     Successfully set the default response header.
     * @retval OT_ERROR_NO_BUFS  Insufficient message buffers available to set the default response header.
     *
     */
    otError SetDefaultResponseHeader(const Message &aRequest);

#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

    /**
     * This method sets the block number value in the message HelpData.
     *
     * @param[in]   aBlockNumber    Block number value to set.
     *
     */
    void SetBlockWiseBlockNumber(uint32_t aBlockNumber) { GetHelpData().mBlockWiseData.mBlockNumber = aBlockNumber; }

    /**
     * This method sets the More Blocks falg in the message HelpData.
     *
     * @param[in]   aMoreBlocks    TRUE or FALSE.
     *
     */
    void SetMoreBlocksFlag(bool aMoreBlocks) { GetHelpData().mBlockWiseData.mMoreBlocks = aMoreBlocks; }

    /**
     * This method sets the block size value in the message HelpData.
     *
     * @param[in]   aBlockSize    Block size value to set.
     *
     */
    void SetBlockWiseBlockSize(otCoapOptionBlockSize aBlockSize)
    {
        GetHelpData().mBlockWiseData.mBlockSize = aBlockSize;
    }
#endif

    /**
     * This method checks if a header is an empty message header.
     *
     * @retval TRUE   Message is an empty message header.
     * @retval FALSE  Message is not an empty message header.
     *
     */
    bool IsEmpty(void) const { return (GetCode() == 0); }

    /**
     * This method checks if a header is a request header.
     *
     * @retval TRUE   Message is a request header.
     * @retval FALSE  Message is not a request header.
     *
     */
    bool IsRequest(void) const { return (GetCode() >= OT_COAP_CODE_GET && GetCode() <= OT_COAP_CODE_DELETE); }

    /**
     * This method checks if a header is a response header.
     *
     * @retval TRUE   Message is a response header.
     * @retval FALSE  Message is not a response header.
     *
     */
    bool IsResponse(void) const { return (GetCode() >= OT_COAP_CODE_RESPONSE_MIN); }

    /**
     * This method checks if a header is a CON message header.
     *
     * @retval TRUE   Message is a CON message header.
     * @retval FALSE  Message is not is a CON message header.
     *
     */
    bool IsConfirmable(void) const { return (GetType() == OT_COAP_TYPE_CONFIRMABLE); }

    /**
     * This method checks if a header is a NON message header.
     *
     * @retval TRUE   Message is a NON message header.
     * @retval FALSE  Message is not is a NON message header.
     *
     */
    bool IsNonConfirmable(void) const { return (GetType() == OT_COAP_TYPE_NON_CONFIRMABLE); }

    /**
     * This method checks if a header is a ACK message header.
     *
     * @retval TRUE   Message is a ACK message header.
     * @retval FALSE  Message is not is a ACK message header.
     *
     */
    bool IsAck(void) const { return (GetType() == OT_COAP_TYPE_ACKNOWLEDGMENT); }

    /**
     * This method checks if a header is a RST message header.
     *
     * @retval TRUE   Message is a RST message header.
     * @retval FALSE  Message is not is a RST message header.
     *
     */
    bool IsReset(void) const { return (GetType() == OT_COAP_TYPE_RESET); }

    /**
     * This method creates a copy of this CoAP message.
     *
     * It allocates the new message from the same message pool as the original one and copies @p aLength octets
     * of the payload. The `Type`, `SubType`, `LinkSecurity`, `Offset`, `InterfaceId`, and `Priority` fields on the
     * cloned message are also copied from the original one.
     *
     * @param[in] aLength  Number of payload bytes to copy.
     *
     * @returns A pointer to the message or NULL if insufficient message buffers are available.
     *
     */
    Message *Clone(uint16_t aLength) const;

    /**
     * This method creates a copy of the message.
     *
     * It allocates the new message from the same message pool as the original one and copies the entire payload. The
     * `Type`, `SubType`, `LinkSecurity`, `Offset`, `InterfaceId`, and `Priority` fields on the cloned message are also
     * copied from the original one.
     *
     * @returns A pointer to the message or NULL if insufficient message buffers are available.
     *
     */
    Message *Clone(void) const { return Clone(GetLength()); }

    /**
     * This method returns the minimal reserved bytes required for CoAP message.
     *
     */
    static uint16_t GetHelpDataReserved(void) { return sizeof(HelpData) + kHelpDataAlignment; }

private:
    /**
     * Protocol Constants (RFC 7252).
     *
     */
    enum
    {
        kOptionDeltaOffset = 4,                         ///< Delta Offset
        kOptionDeltaMask   = 0xf << kOptionDeltaOffset, ///< Delta Mask

        kMaxTokenLength = OT_COAP_MAX_TOKEN_LENGTH,

        kVersionMask   = 0xc0, ///< Version mask as specified (RFC 7252).
        kVersionOffset = 6,    ///< Version offset as specified (RFC 7252).

        kTypeMask = 0x30, ///< Type mask as specified (RFC 7252).

        kTokenLengthMask   = 0x0f, ///< Token Length mask as specified (RFC 7252).
        kTokenLengthOffset = 0,    ///< Token Length offset as specified (RFC 7252).
        kTokenOffset       = 4,    ///< Token offset as specified (RFC 7252).

        kMaxOptionHeaderSize = 5, ///< Maximum size of an Option header

        kOption1ByteExtension = 13, ///< Indicates a 1 byte extension (RFC 7252).
        kOption2ByteExtension = 14, ///< Indicates a 1 byte extension (RFC 7252).

        kOption1ByteExtensionOffset = 13,  ///< Delta/Length offset as specified (RFC 7252).
        kOption2ByteExtensionOffset = 269, ///< Delta/Length offset as specified (RFC 7252).

        kHelpDataAlignment = sizeof(uint16_t), ///< Alignment of help data.
    };

    enum
    {
        kBlockSzxOffset = 0,
        kBlockMOffset   = 3,
        kBlockNumOffset = 4,
    };

    enum
    {
        kBlockNumMax = 0xFFFFF,
    };

#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    OT_TOOL_PACKED_BEGIN
    struct BlockWiseData
    {
        uint32_t              mBlockNumber;
        bool                  mMoreBlocks;
        otCoapOptionBlockSize mBlockSize;
    } OT_TOOL_PACKED_END;
#endif

    /**
     * This structure represents a CoAP header excluding CoAP options.
     *
     */
    OT_TOOL_PACKED_BEGIN
    struct Header
    {
        uint8_t  mVersionTypeToken;                ///< The CoAP Version, Type, and Token Length
        uint8_t  mCode;                            ///< The CoAP Code
        uint16_t mMessageId;                       ///< The CoAP Message ID
        uint8_t  mToken[OT_COAP_MAX_TOKEN_LENGTH]; ///< The CoAP Token
    } OT_TOOL_PACKED_END;

    /**
     * This structure represents a HelpData used by this CoAP message.
     *
     */
    struct HelpData
    {
        void Clear(void) { memset(this, 0, sizeof(*this)); }

        Header   mHeader;
        uint16_t mOptionLast;
        uint16_t mHeaderOffset; ///< The byte offset for the CoAP Header
        uint16_t mHeaderLength;
#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
        BlockWiseData mBlockWiseData;
#endif
    };

    const HelpData &GetHelpData(void) const
    {
        OT_STATIC_ASSERT(sizeof(mBuffer.mHead.mInfo) + sizeof(HelpData) + kHelpDataAlignment <= sizeof(mBuffer),
                         "Insufficient buffer size for CoAP processing!");

        return *static_cast<const HelpData *>(OT_ALIGN(mBuffer.mHead.mData, kHelpDataAlignment));
    }

    HelpData &GetHelpData(void) { return const_cast<HelpData &>(static_cast<const Message *>(this)->GetHelpData()); }
};

class OptionIterator : public ::otCoapOptionIterator
{
public:
    /**
     * Initialise the state of the iterator to iterate over the given message.
     *
     * @retval  OT_ERROR_NONE   Successfully initialised
     * @retval  OT_ERROR_PARSE  Message state is inconsistent
     *
     */
    otError Init(const Message *aMessage);

    /**
     * This method returns a pointer to the first option.
     *
     * @returns A pointer to the first option. If no option is present NULL pointer is returned.
     */
    const otCoapOption *GetFirstOption(void);

    /**
     * This method returns a pointer to the next option.
     *
     * @returns A pointer to the next option. If no more options are present NULL pointer is returned.
     */
    const otCoapOption *GetNextOption(void);

    /**
     * This function fills current option value into @p aValue.
     *
     * @retval  OT_ERROR_NONE       Successfully filled value.
     * @retval  OT_ERROR_NOT_FOUND  No more options, mNextOptionOffset is set to offset of payload.
     *
     */
    otError GetOptionValue(void *aValue) const;

    /**
     * This function returns a pointer to the otCoapOption that matches aNumber
     *
     * @returns A pointer to the wanted option. If this option is not present NULL pointer is returned.
     */
    const otCoapOption *GetOptionByNumber(uint16_t aNumber);

private:
    void           ClearOption(void) { memset(&mOption, 0, sizeof(mOption)); }
    const Message &GetMessage(void) const { return *static_cast<const Message *>(mMessage); }
};

/**
 * @}
 *
 */

} // namespace Coap
} // namespace ot

#endif // COAP_HEADER_HPP_
