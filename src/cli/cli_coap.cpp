/*
 *  Copyright (c) 2017, The OpenThread Authors.
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
 *   This file implements a simple CLI for the CoAP service.
 */

#include "cli_coap.hpp"

//#if OPENTHREAD_CONFIG_COAP_API_ENABLE

#include <ctype.h>

#include "cli/cli.hpp"
#include "cli/cli_server.hpp"
#include "coap/coap_message.hpp"

#define TEST_BLOCK_WISE_PAYLOAD "Lorem ipsum dolor sit amet, cum ea consul iriure i"    \
                                "ntellegat, duo omnes oratio consetetur cu. Verear "    \
                                "ullamcorper sea in, sea rebum prompta ne. Eu sint "    \
                                "aliquip vis. Eirmod nostrud mnesarchum pro ad, nam"    \
                                " at doctus impedit accusamus. Ex qui soleat conven"    \
                                "ire, nobis adversarium efficiantur at sea, te vim "    \
                                "tale partem. Vix diam erat nostro ex, qui volumus "    \
                                "voluptua deseruisse et. Veri accusam has no, scaev"    \
                                "ola scriptorem ex sit. Qui hendrerit assueverit ne"    \
                                ", ea mei wisi praesent. Eam natum melius virtute e"    \
                                "x. Ei nam partem copiosae torquatos. Solet tation "    \
                                "pro no. Usu in solum noluisse. Ea dico aliquando v"    \
                                "oluptaria vix, ludus tollit est ne. Ex usu corrump"    \
                                "it sententiae, ad vix quaeque laoreet referrentur."    \
                                " Nihil evertitur posidonium te per, augue oratio e"    \
                                "vertitur nec id, iriure lobortis sententiae ut eos"    \
                                ". Eam scripta adipiscing concludaturque ei. Nec vi"    \
                                "ris zril sanctus in, ut cibo everti tamquam cum, s"    \
                                "it ridens ceteros ei. Id has primis nominavi expet"    \
                                "endis, at nam consul senserit consequuntur. Nec ut"    \
                                " suas habemus, vix in vivendum prodesset. Eu per f"    \
                                "erri possit rationibus. Pri ea civibus lobortis pe"    \
                                "rtinax. Regione omnesque eleifend te vis. Vim ride"    \
                                "ns elaboraret ut, nec ea velit error legimus, fabu"    \
                                "las facilisis elaboraret ex est. Suavitate signife"    \
                                "rumque te usu, per fastidii adipisci no. Sed aperi"    \
                                "am corpora principes at. Mel everti mediocrem cu, "    \
                                "mnesarchum scriptorem usu no, quando eligendi dign"    \
                                "issim ut ius. Cu has viris libris, pri ut ceteros "    \
                                "nusquam invidunt, corpora rationibus philosophia p"    \
                                "er te. Aeterno mediocrem patrioque eu est, quot ob"    \
                                "lique laboramus per ne. Eirmod facilisis conclusio"    \
                                "nemque mei ea, ut eos illud tempor complectitur. L"    \
                                "obortis honestatis ne vis. Scaevola inimicus sed n"    \
                                "o, at soleat evertitur his, quis dolores prodesset"    \
                                " cu per. Partem dictas vel ne, vel no quod nulla s"    \
                                "onet, ut aliquam inimicus recteque duo. Sit cu vid"    \
                                "isse assentior. Quo an autem putent, nec in legere"    \
                                " detracto petentium. Elit timeam no est. Wisi voce"    \
                                "nt eleifend his ei. Ex has prima saperet epicuri, "    \
                                "at nec fabellas intellegam. Reque laoreet propriae"    \
                                " ne nam. Vim dicant maluisset ut, ex vim wisi grae"    \
                                "ce, eum labore facete id."

namespace ot {
namespace Cli {

const struct Coap::Command Coap::sCommands[] = {
    {"help", &Coap::ProcessHelp},         {"delete", &Coap::ProcessRequest},
    {"get", &Coap::ProcessRequest},       {"parameters", &Coap::ProcessParameters},
    {"post", &Coap::ProcessRequest},      {"put", &Coap::ProcessRequest},
    {"resource", &Coap::ProcessResource}, {"start", &Coap::ProcessStart},
    {"stop", &Coap::ProcessStop},
#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    {"blocksize", &Coap::ProcessBlocksize},
#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
};

Coap::Coap(Interpreter &aInterpreter)
    : mInterpreter(aInterpreter)
    , mUseDefaultRequestTxParameters(true)
    , mUseDefaultResponseTxParameters(true)
{
    memset(&mResource, 0, sizeof(mResource));
}

void Coap::PrintPayload(otMessage *aMessage) const
{
    uint8_t  buf[kMaxBufferSize];
    uint16_t bytesToPrint;
    uint16_t bytesPrinted = 0;
    uint16_t length       = otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
    // scnm test begin
    bool payloadCorrect = true;
    // scnm test end

    if (length > 0)
    {
        mInterpreter.mServer->OutputFormat(" with payload: ");

        // scnm test begin
        if ((otMessageGetLength(aMessage) - otMessageGetOffset(aMessage)) >
            (1 << (4 + otCoapGetMaxBlockSize(mInterpreter.mInstance))))
        {
            while (length > 0)
            {
                bytesToPrint = (length < sizeof(buf)) ? length : sizeof(buf);
                otMessageRead(aMessage, otMessageGetOffset(aMessage) + bytesPrinted, buf, bytesToPrint);

                if (memcmp(buf, TEST_BLOCK_WISE_PAYLOAD + bytesPrinted, bytesToPrint) != 0)
                {
                    payloadCorrect = false;
                    break;
                }

                length -= bytesToPrint;
                bytesPrinted += bytesToPrint;
            }

            if (payloadCorrect)
            {
                mInterpreter.mServer->OutputFormat("test-payload correct");
            }
            else
            {
                mInterpreter.mServer->OutputFormat("test-payload incorrect");
            }
        }
        else
        {
        // scnm test end
            while (length > 0)
            {
                bytesToPrint = (length < sizeof(buf)) ? length : sizeof(buf);
                otMessageRead(aMessage, otMessageGetOffset(aMessage) + bytesPrinted, buf, bytesToPrint);

                mInterpreter.OutputBytes(buf, static_cast<uint8_t>(bytesToPrint));

                length -= bytesToPrint;
                bytesPrinted += bytesToPrint;

                // scnm test begin
                if (bytesPrinted % (4 * kMaxBufferSize) == 0)
                {
                    mInterpreter.mServer->OutputFormat("\r\n");
                }
                // scnm test end
            }
        }
    }

    mInterpreter.mServer->OutputFormat("\r\n");
}

otError Coap::ProcessHelp(int argc, char *argv[])
{
    OT_UNUSED_VARIABLE(argc);
    OT_UNUSED_VARIABLE(argv);

    for (size_t i = 0; i < OT_ARRAY_LENGTH(sCommands); i++)
    {
        mInterpreter.mServer->OutputFormat("%s\r\n", sCommands[i].mName);
    }

    return OT_ERROR_NONE;
}

otError Coap::ProcessResource(int argc, char *argv[])
{
    otError error = OT_ERROR_NONE;

    if (argc > 1)
    {
        VerifyOrExit(strlen(argv[1]) < kMaxUriLength, error = OT_ERROR_INVALID_ARGS);

        mResource.mUriPath = mUriPath;
        mResource.mContext = this;
        mResource.mHandler = &Coap::HandleRequest;

        strncpy(mUriPath, argv[1], sizeof(mUriPath) - 1);
        SuccessOrExit(error = otCoapAddResource(mInterpreter.mInstance, &mResource));
    }
    else
    {
        mInterpreter.mServer->OutputFormat("%s\r\n", mResource.mUriPath);
    }

exit:
    return OT_ERROR_NONE;
}

otError Coap::ProcessStart(int argc, char *argv[])
{
    OT_UNUSED_VARIABLE(argc);
    OT_UNUSED_VARIABLE(argv);

    return otCoapStart(mInterpreter.mInstance, OT_DEFAULT_COAP_PORT);
}

otError Coap::ProcessStop(int argc, char *argv[])
{
    OT_UNUSED_VARIABLE(argc);
    OT_UNUSED_VARIABLE(argv);

    otCoapRemoveResource(mInterpreter.mInstance, &mResource);

    return otCoapStop(mInterpreter.mInstance);
}

otError Coap::ProcessParameters(int argc, char *argv[])
{
    otError error = OT_ERROR_NONE;

    VerifyOrExit(argc > 0, error = OT_ERROR_INVALID_ARGS);

    bool *              defaultTxParameters;
    otCoapTxParameters *txParameters;

    if (strcmp(argv[1], "request") == 0)
    {
        txParameters        = &mRequestTxParameters;
        defaultTxParameters = &mUseDefaultRequestTxParameters;
    }
    else if (strcmp(argv[1], "response") == 0)
    {
        txParameters        = &mResponseTxParameters;
        defaultTxParameters = &mUseDefaultResponseTxParameters;
    }
    else
    {
        ExitNow(error = OT_ERROR_INVALID_ARGS);
    }

    if (argc > 2)
    {
        if (strcmp(argv[2], "default") == 0)
        {
            *defaultTxParameters = true;
        }
        else
        {
            unsigned long value;

            VerifyOrExit(argc >= 6, error = OT_ERROR_INVALID_ARGS);

            SuccessOrExit(error = mInterpreter.ParseUnsignedLong(argv[2], value));
            txParameters->mAckTimeout = static_cast<uint32_t>(value);

            SuccessOrExit(error = mInterpreter.ParseUnsignedLong(argv[3], value));
            VerifyOrExit(value <= 255, error = OT_ERROR_INVALID_ARGS);
            txParameters->mAckRandomFactorNumerator = static_cast<uint8_t>(value);

            SuccessOrExit(error = mInterpreter.ParseUnsignedLong(argv[4], value));
            VerifyOrExit(value <= 255, error = OT_ERROR_INVALID_ARGS);
            txParameters->mAckRandomFactorDenominator = static_cast<uint8_t>(value);

            SuccessOrExit(error = mInterpreter.ParseUnsignedLong(argv[5], value));
            VerifyOrExit(value <= 255, error = OT_ERROR_INVALID_ARGS);
            txParameters->mMaxRetransmit = static_cast<uint8_t>(value);

            VerifyOrExit(txParameters->mAckRandomFactorNumerator > txParameters->mAckRandomFactorDenominator,
                         error = OT_ERROR_INVALID_ARGS);

            *defaultTxParameters = false;
        }
    }

    mInterpreter.mServer->OutputFormat("Transmission parameters for %s:\r\n", argv[1]);
    if (*defaultTxParameters)
    {
        mInterpreter.mServer->OutputFormat("default\r\n");
    }
    else
    {
        mInterpreter.mServer->OutputFormat("ACK_TIMEOUT=%u ms, ACK_RANDOM_FACTOR=%u/%u, MAX_RETRANSMIT=%u\r\n",
                                           txParameters->mAckTimeout, txParameters->mAckRandomFactorNumerator,
                                           txParameters->mAckRandomFactorDenominator, txParameters->mMaxRetransmit);
    }

exit:
    return error;
}

otError Coap::ProcessRequest(int argc, char *argv[])
{
    otError       error   = OT_ERROR_NONE;
    otMessage *   message = NULL;
    otMessageInfo messageInfo;
    uint16_t      payloadLength = 0;

    // Default parameters
    char         coapUri[kMaxUriLength] = "test";
    otCoapType   coapType               = OT_COAP_TYPE_NON_CONFIRMABLE;
    otCoapCode   coapCode               = OT_COAP_CODE_GET;
    otIp6Address coapDestinationIp;

    VerifyOrExit(argc > 0, error = OT_ERROR_INVALID_ARGS);

    // CoAP-Code
    if (strcmp(argv[0], "get") == 0)
    {
        coapCode = OT_COAP_CODE_GET;
    }
    else if (strcmp(argv[0], "post") == 0)
    {
        coapCode = OT_COAP_CODE_POST;
    }
    else if (strcmp(argv[0], "put") == 0)
    {
        coapCode = OT_COAP_CODE_PUT;
    }
    else if (strcmp(argv[0], "delete") == 0)
    {
        coapCode = OT_COAP_CODE_DELETE;
    }
    else
    {
        ExitNow(error = OT_ERROR_INVALID_ARGS);
    }

    // Destination IPv6 address
    if (argc > 1)
    {
        SuccessOrExit(error = otIp6AddressFromString(argv[1], &coapDestinationIp));
    }
    else
    {
        ExitNow(error = OT_ERROR_INVALID_ARGS);
    }

    // CoAP-URI
    if (argc > 2)
    {
        VerifyOrExit(strlen(argv[2]) < kMaxUriLength, error = OT_ERROR_INVALID_ARGS);
        strncpy(coapUri, argv[2], sizeof(coapUri) - 1);
    }
    else
    {
        ExitNow(error = OT_ERROR_INVALID_ARGS);
    }

    // CoAP-Type
    if (argc > 3)
    {
        if (strcmp(argv[3], "con") == 0)
        {
            coapType = OT_COAP_TYPE_CONFIRMABLE;
        }
    }

    message = otCoapNewMessage(mInterpreter.mInstance, NULL);
    VerifyOrExit(message != NULL, error = OT_ERROR_NO_BUFS);

    otCoapMessageInit(message, coapType, coapCode);
    otCoapMessageGenerateToken(message, ot::Coap::Message::kDefaultTokenLength);
    SuccessOrExit(error = otCoapMessageAppendUriPathOptions(message, coapUri));

    if (argc > 4)
    {
        // scnm test begin
#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
        if (strcmp(argv[4], "test-payload") == 0)
        {
            payloadLength = sizeof(TEST_BLOCK_WISE_PAYLOAD);
        }
        else
        {
            payloadLength = static_cast<uint16_t>(strlen(argv[4]));
        }
#else
        payloadLength = static_cast<uint16_t>(strlen(argv[4]));
#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
       // scnm test end
       // payloadLength = static_cast<uint16_t>(strlen(argv[4]));

        if (payloadLength > 0)
        {
            SuccessOrExit(error = otCoapMessageSetPayloadMarker(message));
        }
    }

    // Embed content into message if given
    if (payloadLength > 0)
    {
        // scnm test begin
#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
        if (strcmp(argv[4], "test-payload") == 0)
        {
            SuccessOrExit(error = otMessageAppend(message, TEST_BLOCK_WISE_PAYLOAD, payloadLength));
        }
        else
        {
            SuccessOrExit(error = otMessageAppend(message, argv[4], payloadLength));
        }
#else
        SuccessOrExit(error = otMessageAppend(message, argv[4], payloadLength));
#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
       // scnm test end
       // SuccessOrExit(error = otMessageAppend(message, argv[4], payloadLength));
    }

    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr = coapDestinationIp;
    messageInfo.mPeerPort = OT_DEFAULT_COAP_PORT;

    if ((coapType == OT_COAP_TYPE_CONFIRMABLE) || (coapCode == OT_COAP_CODE_GET))
    {
        error = otCoapSendRequestWithParameters(mInterpreter.mInstance, message, &messageInfo, &Coap::HandleResponse,
                                                this, GetRequestTxParameters());
    }
    else
    {
        error = otCoapSendRequestWithParameters(mInterpreter.mInstance, message, &messageInfo, NULL, NULL,
                                                GetResponseTxParameters());
    }

exit:

    if ((error != OT_ERROR_NONE) && (message != NULL))
    {
        otMessageFree(message);
    }

    return error;
}

#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
otError Coap::ProcessBlocksize(int argc, char *argv[])
{
    otError error = OT_ERROR_NONE;

    if (argc > 1)
    {
        if (strcmp(argv[1], "1024") == 0)
        {
            otCoapSetMaxBlockSize(mInterpreter.mInstance, OT_COAP_OPTION_BLOCK_LENGTH_1024);
        }
        else if (strcmp(argv[1], "512") == 0)
        {
            otCoapSetMaxBlockSize(mInterpreter.mInstance, OT_COAP_OPTION_BLOCK_LENGTH_512);
        }
        else if (strcmp(argv[1], "256") == 0)
        {
            otCoapSetMaxBlockSize(mInterpreter.mInstance, OT_COAP_OPTION_BLOCK_LENGTH_256);
        }
        else if (strcmp(argv[1], "128") == 0)
        {
            otCoapSetMaxBlockSize(mInterpreter.mInstance, OT_COAP_OPTION_BLOCK_LENGTH_128);
        }
        else if (strcmp(argv[1], "64") == 0)
        {
            otCoapSetMaxBlockSize(mInterpreter.mInstance, OT_COAP_OPTION_BLOCK_LENGTH_64);
        }
        else if (strcmp(argv[1], "32") == 0)
        {
            otCoapSetMaxBlockSize(mInterpreter.mInstance, OT_COAP_OPTION_BLOCK_LENGTH_32);
        }
        else if (strcmp(argv[1], "16") == 0)
        {
            otCoapSetMaxBlockSize(mInterpreter.mInstance, OT_COAP_OPTION_BLOCK_LENGTH_16);
        }
        else
        {
            ExitNow(error = OT_ERROR_INVALID_ARGS);
        }
    }
    else
    {
        mInterpreter.mServer->OutputFormat("%d\r\n", 1 << (4 + otCoapGetMaxBlockSize(mInterpreter.mInstance)));
    }

exit:
    return error;
}
#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

otError Coap::Process(int argc, char *argv[])
{
    otError error = OT_ERROR_PARSE;

    if (argc < 1)
    {
        ProcessHelp(0, NULL);
        error = OT_ERROR_INVALID_ARGS;
    }
    else
    {
        for (size_t i = 0; i < OT_ARRAY_LENGTH(sCommands); i++)
        {
            if (strcmp(argv[0], sCommands[i].mName) == 0)
            {
                error = (this->*sCommands[i].mCommand)(argc, argv);
                break;
            }
        }
    }

    return error;
}

void Coap::HandleRequest(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    static_cast<Coap *>(aContext)->HandleRequest(aMessage, aMessageInfo);
}

void Coap::HandleRequest(otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    otError    error             = OT_ERROR_NONE;
    otMessage *responseMessage   = NULL;
    otCoapCode responseCode      = OT_COAP_CODE_EMPTY;
#if !OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE   // scnm test begin
    char       responseContent[] = "helloWorld";
#endif  // scnm test end

    mInterpreter.mServer->OutputFormat("coap request from ");
    mInterpreter.OutputIp6Address(aMessageInfo->mPeerAddr);
    mInterpreter.mServer->OutputFormat(" ");

    switch (otCoapMessageGetCode(aMessage))
    {
    case OT_COAP_CODE_GET:
        mInterpreter.mServer->OutputFormat("GET");
        break;

    case OT_COAP_CODE_DELETE:
        mInterpreter.mServer->OutputFormat("DELETE");
        break;

    case OT_COAP_CODE_PUT:
        mInterpreter.mServer->OutputFormat("PUT");
        break;

    case OT_COAP_CODE_POST:
        mInterpreter.mServer->OutputFormat("POST");
        break;

    default:
        mInterpreter.mServer->OutputFormat("Undefined\r\n");
        ExitNow(error = OT_ERROR_PARSE);
    }

    PrintPayload(aMessage);

    if (otCoapMessageGetType(aMessage) == OT_COAP_TYPE_CONFIRMABLE ||
        otCoapMessageGetCode(aMessage) == OT_COAP_CODE_GET)
    {
        if (otCoapMessageGetCode(aMessage) == OT_COAP_CODE_GET)
        {
            responseCode = OT_COAP_CODE_CONTENT;
        }
        else
        {
            responseCode = OT_COAP_CODE_VALID;
        }

        responseMessage = otCoapNewMessage(mInterpreter.mInstance, NULL);
        VerifyOrExit(responseMessage != NULL, error = OT_ERROR_NO_BUFS);

        SuccessOrExit(
            error = otCoapMessageInitResponse(responseMessage, aMessage, OT_COAP_TYPE_ACKNOWLEDGMENT, responseCode));

        if (otCoapMessageGetCode(aMessage) == OT_COAP_CODE_GET)
        {
            SuccessOrExit(error = otCoapMessageSetPayloadMarker(responseMessage));
            // scnm test begin
#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
            SuccessOrExit(
                error = otMessageAppend(responseMessage, TEST_BLOCK_WISE_PAYLOAD, sizeof(TEST_BLOCK_WISE_PAYLOAD)));
#else
            SuccessOrExit(error = otMessageAppend(responseMessage, &responseContent, sizeof(responseContent)));
#endif
            // scnm test end
            // SuccessOrExit(error = otMessageAppend(responseMessage, &responseContent, sizeof(responseContent)));
        }

        SuccessOrExit(error = otCoapSendResponseWithParameters(mInterpreter.mInstance, responseMessage, aMessageInfo,
                                                               GetResponseTxParameters()));
    }

exit:

    if (error != OT_ERROR_NONE)
    {
        if (responseMessage != NULL)
        {
            mInterpreter.mServer->OutputFormat("coap send response error %d: %s\r\n", error,
                                               otThreadErrorToString(error));
            otMessageFree(responseMessage);
        }
    }
    else if (responseCode >= OT_COAP_CODE_RESPONSE_MIN)
    {
        mInterpreter.mServer->OutputFormat("coap response sent\r\n");
    }
}

void Coap::HandleResponse(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo, otError aError)
{
    static_cast<Coap *>(aContext)->HandleResponse(aMessage, aMessageInfo, aError);
}

void Coap::HandleResponse(otMessage *aMessage, const otMessageInfo *aMessageInfo, otError aError)
{
    if (aError != OT_ERROR_NONE)
    {
        mInterpreter.mServer->OutputFormat("coap receive response error %d: %s\r\n", aError,
                                           otThreadErrorToString(aError));
    }
    else
    {
        mInterpreter.mServer->OutputFormat("coap response from ");
        mInterpreter.OutputIp6Address(aMessageInfo->mPeerAddr);

        PrintPayload(aMessage);
    }
}

} // namespace Cli
} // namespace ot

//#endif // OPENTHREAD_CONFIG_COAP_API_ENABLE
