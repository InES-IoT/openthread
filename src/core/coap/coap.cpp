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

#include "coap.hpp"

#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/instance.hpp"
#include "common/locator-getters.hpp"
#include "common/logging.hpp"
#include "common/random.hpp"
#include "net/ip6.hpp"
#include "net/udp6.hpp"
#include "thread/thread_netif.hpp"

/**
 * @file
 *   This file contains common code base for CoAP client and server.
 */

namespace ot {
namespace Coap {

CoapBase::CoapBase(Instance &aInstance, Sender aSender)
    : InstanceLocator(aInstance)
    , mRetransmissionTimer(aInstance, &Coap::HandleRetransmissionTimer, this)
    , mResources()
    , mContext(NULL)
    , mInterceptor(NULL)
    , mResponsesQueue(aInstance)
    , mDefaultHandler(NULL)
    , mDefaultHandlerContext(NULL)
    , mSender(aSender)
    //#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    , mCurrentMaxBlockSize(OT_COAP_OPTION_BLOCK_SZX_1024)
    , mLastResponse(NULL)
    , mIsBlockWiseTransferActive(false)
    , mHasLastBlockBeenReceived(false)
//#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
{
    mMessageId = Random::NonCrypto::GetUint16();
}

void CoapBase::ClearRequestsAndResponses(void)
{
    Message *    message = static_cast<Message *>(mPendingRequests.GetHead());
    Message *    messageToRemove;
    CoapMetadata coapMetadata;

    // Remove all pending messages.
    while (message != NULL)
    {
        messageToRemove = message;
        message         = static_cast<Message *>(message->GetNext());

        coapMetadata.ReadFrom(*messageToRemove);
        FinalizeCoapTransaction(*messageToRemove, coapMetadata, NULL, NULL, OT_ERROR_ABORT);
    }

    mResponsesQueue.DequeueAllResponses();
}

void CoapBase::ClearRequests(const Ip6::Address &aAddress)
{
    Message *nextMessage;

    // Remove pending messages with the specified source.
    for (Message *message = static_cast<Message *>(mPendingRequests.GetHead()); message != NULL; message = nextMessage)
    {
        CoapMetadata coapMetadata;
        nextMessage = static_cast<Message *>(message->GetNext());
        coapMetadata.ReadFrom(*message);

        if (coapMetadata.mSourceAddress == aAddress)
        {
            FinalizeCoapTransaction(*message, coapMetadata, NULL, NULL, OT_ERROR_ABORT);
        }
    }
}

otError CoapBase::AddResource(Resource &aResource)
{
    return mResources.Add(aResource);
}

void CoapBase::RemoveResource(Resource &aResource)
{
    mResources.Remove(aResource);
    aResource.SetNext(NULL);
}

void CoapBase::SetDefaultHandler(otCoapRequestHandler aHandler, void *aContext)
{
    mDefaultHandler        = aHandler;
    mDefaultHandlerContext = aContext;
}

Message *CoapBase::NewMessage(const otMessageSettings *aSettings)
{
    Message *message = NULL;

    VerifyOrExit((message = static_cast<Message *>(Get<Ip6::Udp>().NewMessage(0, aSettings))) != NULL);
    message->SetOffset(0);

exit:
    return message;
}

#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
otError CoapBase::SendMessage(Message &                   aMessage,
                              const Ip6::MessageInfo &    aMessageInfo,
                              otCoapResponseHandler       aHandler,
                              void *                      aContext,
                              otCoapBlockwiseTransmitHook aTransmitHook,
                              otCoapBlockwiseReceiveHook  aReceiveHook)
{
    otError      error = OT_ERROR_NONE;
    CoapMetadata coapMetadata;
    Message *    message    = NULL;
    Message *    storedCopy = NULL;
    uint16_t     copyLength = 0;

    // Check if blockwise transfer is necessary
    // TODO: initiate blockwise transfer
    /*if ((aMessage.GetLength() - aMessage.GetHeaderLength() > 1 << (4 + mCurrentMaxBlockSize)) ||
        mHasLastBlockBeenReceived)
    {
        // Check if message payload is longer than allowed for blockwise transfer
        VerifyOrExit(aMessage.GetLength() - aMessage.GetHeaderLength() < kMaxBodyLength, error = OT_ERROR_NO_BUFS);
        // Check if blockwise transfer is running
        VerifyOrExit(!mIsBlockWiseTransferActive, error = OT_ERROR_BUSY);

        VerifyOrExit((message = NewMessage()) != NULL, error = OT_ERROR_NO_BUFS);

        aMessage.Finish();

        if (aMessage.GetLength() - aMessage.GetHeaderLength() > 1 << (4 + mCurrentMaxBlockSize))
        {
            if ((error = InitiateBlockWiseTransfer(&aMessage, message)) != OT_ERROR_NONE)
            {
                message->Free();
                ExitNow();
            }

            mIsBlockWiseTransferActive = true;
        }
        else
        {
            // Conclude Block1 transfer
            if ((error = FinishBlock1Transfer(aMessage, *message)) != OT_ERROR_NONE)
            {
                message->Free();
                ExitNow();
            }
        }

        if (mHasLastBlockBeenReceived)
        {
            mHasLastBlockBeenReceived = false;
        }
    }
    else
    {*/
    message = &aMessage;
    //}

    if ((message->GetType() == OT_COAP_TYPE_ACKNOWLEDGMENT || message->GetType() == OT_COAP_TYPE_RESET) &&
        message->GetCode() != OT_COAP_CODE_EMPTY)
    {
        mResponsesQueue.EnqueueResponse(*message, aMessageInfo);
    }

    // Set Message Id if it was not already set.
    if (message->GetMessageId() == 0 &&
        (message->GetType() == OT_COAP_TYPE_CONFIRMABLE || message->GetType() == OT_COAP_TYPE_NON_CONFIRMABLE))
    {
        message->SetMessageId(mMessageId++);
    }

    message->Finish();

    if (message->IsConfirmable())
    {
        // Create a copy of entire message and enqueue it.
        copyLength = message->GetLength();
    }
    else if (message->IsNonConfirmable() && (aHandler != NULL))
    {
        // As we do not retransmit non confirmable messages, create a copy of header only, for token information.
        copyLength = message->GetOptionStart();
    }

    if (copyLength > 0)
    {
        coapMetadata =
            CoapMetadata(message->IsConfirmable(), aMessageInfo, aHandler, aContext, aReceiveHook, aTransmitHook);
        VerifyOrExit((storedCopy = CopyAndEnqueueMessage(*message, copyLength, coapMetadata)) != NULL,
                     error = OT_ERROR_NO_BUFS);
    }

    SuccessOrExit(error = Send(*message, aMessageInfo));

exit:

    if (error != OT_ERROR_NONE && storedCopy != NULL)
    {
        DequeueMessage(*storedCopy);
    }

    if (error == OT_ERROR_NONE && message != &aMessage)
    {
        aMessage.Free();
    }

    return error;
}
#else  // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
otError CoapBase::SendMessage(Message &               aMessage,
                              const Ip6::MessageInfo &aMessageInfo,
                              const CoapTxParameters &aTxParameters,
                              otCoapResponseHandler   aHandler,
                              void *                  aContext)
{
    otError  error;
    Message *storedCopy = NULL;
    uint16_t copyLength = 0;

    switch (aMessage.GetType())
    {
    case OT_COAP_TYPE_ACKNOWLEDGMENT:
        mResponsesQueue.EnqueueResponse(aMessage, aMessageInfo, aTxParameters);
        break;
    case OT_COAP_TYPE_RESET:
        assert(aMessage.GetCode() == OT_COAP_CODE_EMPTY);
        break;
    default:
        aMessage.SetMessageId(mMessageId++);
        break;
    }

    aMessage.Finish();

    if (aMessage.IsConfirmable())
    {
        // Create a copy of entire message and enqueue it.
        copyLength = aMessage.GetLength();
    }
    else if (aMessage.IsNonConfirmable() && (aHandler != NULL))
    {
        // As we do not retransmit non confirmable messages, create a copy of header only, for token information.
        copyLength = aMessage.GetOptionStart();
    }

    if (copyLength > 0)
    {
        CoapMetadata coapMetadata =
            CoapMetadata(aMessage.IsConfirmable(), aMessageInfo, aHandler, aContext, aTxParameters);
        VerifyOrExit((storedCopy = CopyAndEnqueueMessage(aMessage, copyLength, coapMetadata)) != NULL,
                     error = OT_ERROR_NO_BUFS);
    }

    SuccessOrExit(error = Send(aMessage, aMessageInfo));

exit:

    if (error != OT_ERROR_NONE && storedCopy != NULL)
    {
        DequeueMessage(*storedCopy);
    }

    return error;
}
#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

otError CoapBase::SendEmptyMessage(Message::Type aType, const Message &aRequest, const Ip6::MessageInfo &aMessageInfo)
{
    otError  error   = OT_ERROR_NONE;
    Message *message = NULL;

    VerifyOrExit(aRequest.GetType() == OT_COAP_TYPE_CONFIRMABLE, error = OT_ERROR_INVALID_ARGS);

    VerifyOrExit((message = NewMessage()) != NULL, error = OT_ERROR_NO_BUFS);

    message->Init(aType, OT_COAP_CODE_EMPTY);
    message->SetMessageId(aRequest.GetMessageId());

    message->Finish();
    SuccessOrExit(error = Send(*message, aMessageInfo));

exit:

    if (error != OT_ERROR_NONE && message != NULL)
    {
        message->Free();
    }

    return error;
}

otError CoapBase::SendHeaderResponse(Message::Code aCode, const Message &aRequest, const Ip6::MessageInfo &aMessageInfo)
{
    otError  error   = OT_ERROR_NONE;
    Message *message = NULL;

    VerifyOrExit(aRequest.IsRequest(), error = OT_ERROR_INVALID_ARGS);
    VerifyOrExit((message = NewMessage()) != NULL, error = OT_ERROR_NO_BUFS);

    switch (aRequest.GetType())
    {
    case OT_COAP_TYPE_CONFIRMABLE:
        message->Init(OT_COAP_TYPE_ACKNOWLEDGMENT, aCode);
        message->SetMessageId(aRequest.GetMessageId());
        break;

    case OT_COAP_TYPE_NON_CONFIRMABLE:
        message->Init(OT_COAP_TYPE_NON_CONFIRMABLE, aCode);
        break;

    default:
        ExitNow(error = OT_ERROR_INVALID_ARGS);
        break;
    }

    SuccessOrExit(error = message->SetToken(aRequest.GetToken(), aRequest.GetTokenLength()));

    SuccessOrExit(error = SendMessage(*message, aMessageInfo));

exit:

    if (error != OT_ERROR_NONE && message != NULL)
    {
        message->Free();
    }

    return error;
}

void CoapBase::HandleRetransmissionTimer(Timer &aTimer)
{
    static_cast<Coap *>(static_cast<TimerMilliContext &>(aTimer).GetContext())->HandleRetransmissionTimer();
}

void CoapBase::HandleRetransmissionTimer(void)
{
    TimeMilli        now      = TimerMilli::GetNow();
    TimeMilli        nextTime = now.GetDistantFuture();
    CoapMetadata     coapMetadata;
    Message *        message;
    Message *        nextMessage;
    Ip6::MessageInfo messageInfo;

    for (message = static_cast<Message *>(mPendingRequests.GetHead()); message != NULL; message = nextMessage)
    {
        nextMessage = static_cast<Message *>(message->GetNext());
        coapMetadata.ReadFrom(*message);

        if (now >= coapMetadata.mNextTimerShot)
        {
            if (!coapMetadata.mConfirmable || (coapMetadata.mRetransmissionsRemaining == 0))
            {
                // No expected response or acknowledgment.
                FinalizeCoapTransaction(*message, coapMetadata, NULL, NULL, OT_ERROR_RESPONSE_TIMEOUT);
                continue;
            }

            // Increment retransmission counter and timer.
            coapMetadata.mRetransmissionsRemaining--;
            coapMetadata.mRetransmissionTimeout *= 2;
            coapMetadata.mNextTimerShot = now + coapMetadata.mRetransmissionTimeout;
            coapMetadata.UpdateIn(*message);

            // Retransmit
            if (!coapMetadata.mAcknowledged)
            {
                messageInfo.SetPeerAddr(coapMetadata.mDestinationAddress);
                messageInfo.SetPeerPort(coapMetadata.mDestinationPort);
                messageInfo.SetSockAddr(coapMetadata.mSourceAddress);

                SendCopy(*message, messageInfo);
            }
        }

        if (nextTime > coapMetadata.mNextTimerShot)
        {
            // No expected response or acknowledgment.
            otLogCritCoap("Message Timeout");
            FinalizeCoapTransaction(*message, coapMetadata, NULL, NULL, OT_ERROR_RESPONSE_TIMEOUT);
        }
    }

    if (nextTime < now.GetDistantFuture())
    {
        mRetransmissionTimer.FireAt(nextTime);
    }
}

void CoapBase::FinalizeCoapTransaction(Message &               aRequest,
                                       const CoapMetadata &    aCoapMetadata,
                                       Message *               aResponse,
                                       const Ip6::MessageInfo *aMessageInfo,
                                       otError                 aResult)
{
    DequeueMessage(aRequest);

    if (aCoapMetadata.mResponseHandler != NULL)
    {
        aCoapMetadata.mResponseHandler(aCoapMetadata.mResponseContext, aResponse, aMessageInfo, aResult);
    }

    //#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    if (mIsBlockWiseTransferActive)
    {
        CleanupBlockWiseTransfer();
    }
    //#endif
}

otError CoapBase::AbortTransaction(otCoapResponseHandler aHandler, void *aContext)
{
    otError      error = OT_ERROR_NOT_FOUND;
    Message *    message;
    Message *    nextMessage;
    CoapMetadata coapMetadata;

    for (message = static_cast<Message *>(mPendingRequests.GetHead()); message != NULL; message = nextMessage)
    {
        nextMessage = static_cast<Message *>(message->GetNext());
        coapMetadata.ReadFrom(*message);

        if (coapMetadata.mResponseHandler == aHandler && coapMetadata.mResponseContext == aContext)
        {
            FinalizeCoapTransaction(*message, coapMetadata, NULL, NULL, OT_ERROR_ABORT);
            error = OT_ERROR_NONE;
        }
    }

    return error;
}

Message *CoapBase::CopyAndEnqueueMessage(const Message &     aMessage,
                                         uint16_t            aCopyLength,
                                         const CoapMetadata &aCoapMetadata)
{
    otError  error       = OT_ERROR_NONE;
    Message *messageCopy = NULL;

    // Create a message copy of requested size.
    VerifyOrExit((messageCopy = aMessage.Clone(aCopyLength)) != NULL, error = OT_ERROR_NO_BUFS);

    // Append the copy with retransmission data.
    SuccessOrExit(error = aCoapMetadata.AppendTo(*messageCopy));

    mRetransmissionTimer.FireAtIfEarlier(aCoapMetadata.mNextTimerShot);

    // Enqueue the message.
    mPendingRequests.Enqueue(*messageCopy);

exit:

    if (error != OT_ERROR_NONE && messageCopy != NULL)
    {
        messageCopy->Free();
        messageCopy = NULL;
    }

    return messageCopy;
}

void CoapBase::DequeueMessage(Message &aMessage)
{
    mPendingRequests.Dequeue(aMessage);

    if (mRetransmissionTimer.IsRunning() && (mPendingRequests.GetHead() == NULL))
    {
        // No more requests pending, stop the timer.
        mRetransmissionTimer.Stop();
    }

    // Free the message memory.
    aMessage.Free();

    // No need to worry that the earliest pending message was removed -
    // the timer would just shoot earlier and then it'd be setup again.
}

//#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

void CoapBase::FreeLastBlockResponse(void)
{
    if (mLastResponse != NULL)
    {
        mLastResponse->Free();
        mLastResponse = NULL;
    }
}

otError CoapBase::CacheLastBlockResponse(Message *aResponse)
{
    // Save last response for block-wise transfer
    FreeLastBlockResponse();

    if ((mLastResponse = aResponse->Clone()) != NULL)
    {
        return OT_ERROR_NONE;
    }
    else
    {
        return OT_ERROR_NO_BUFS;
    }
}

void CoapBase::CleanupBlockWiseTransfer(void)
{
    // Clear all buffers and flags related to block-wise transfer
    mIsBlockWiseTransferActive = false;

    FreeLastBlockResponse();

    otLogDebgCoap("Cleanup block-wise transfer");
}

/*otError CoapBase::InitiateBlockWiseTransfer(Message *aMessage, Message *aMessageOut)
{
    otError        error             = OT_ERROR_NONE;
    bool           isBlock1OptionSet = false;
    bool           isBlock2OptionSet = false;
    uint8_t *      optionBuf         = NULL;
    OptionIterator iterator;

    SuccessOrExit(error = iterator.Init(aMessage));

    memset(mDisassemblyMessage, 0, sizeof(mDisassemblyMessage));
    mDisassemblyMessageLength =
        aMessage->Read(aMessage->GetOffset(), aMessage->GetLength() - aMessage->GetOffset(), mDisassemblyMessage);

    switch (aMessage->GetCode())
    {
    case OT_COAP_CODE_POST:
    case OT_COAP_CODE_PUT:
        // Set CoAP type and code for Block1 transfer
        aMessageOut->Init(OT_COAP_TYPE_CONFIRMABLE, aMessage->GetCode());
        break;

    case OT_COAP_CODE_CREATED:
    case OT_COAP_CODE_VALID:
    case OT_COAP_CODE_CHANGED:
    case OT_COAP_CODE_CONTENT:
        // Set CoAP type and code for Block2 transfer
        aMessageOut->Init(OT_COAP_TYPE_ACKNOWLEDGMENT, aMessage->GetCode());
        break;

    default:
        error = OT_ERROR_INVALID_ARGS;
        ExitNow();
        break;
    }

    aMessageOut->SetToken(aMessage->GetToken(), aMessage->GetTokenLength());
    aMessageOut->SetMessageId(aMessage->GetMessageId());

    // Copy options of original message and add block options
    for (const otCoapOption *option = iterator.GetFirstOption(); option != NULL; option = iterator.GetNextOption())
    {
        VerifyOrExit((optionBuf = (uint8_t *)calloc(option->mLength, sizeof(uint8_t))) != NULL,
                     error = OT_ERROR_NO_BUFS);
        switch (aMessage->GetCode())
        {
        case OT_COAP_CODE_POST:
        case OT_COAP_CODE_PUT:
            // Initiate Block1 transfer
            if (option->mNumber > OT_COAP_OPTION_BLOCK1 && !isBlock1OptionSet)
            {
                SuccessOrExit(error =
                                  aMessageOut->AppendBlockOption(OT_COAP_OPTION_BLOCK1, 0, true, mCurrentMaxBlockSize));
                aMessageOut->SetBlockWiseBlockNumber(0);
                aMessageOut->SetMoreBlocksFlag(true);
                aMessageOut->SetBlockWiseBlockSize(mCurrentMaxBlockSize);
                isBlock1OptionSet = true;
                otLogInfoCoap("Start Block1 transfer");
            }

            iterator.GetOptionValue(optionBuf);
            SuccessOrExit(error = aMessageOut->AppendOption(option->mNumber, option->mLength, optionBuf));
            break;

        case OT_COAP_CODE_CREATED:
        case OT_COAP_CODE_VALID:
        case OT_COAP_CODE_CHANGED:
        case OT_COAP_CODE_CONTENT:
            if (mHasLastBlockBeenReceived)
            {
                // Initiate Block2 transfer
                if (option->mNumber > OT_COAP_OPTION_BLOCK2 && !isBlock2OptionSet)
                {
                    SuccessOrExit(
                        error = aMessageOut->AppendBlockOption(OT_COAP_OPTION_BLOCK2, 0, true, mCurrentMaxBlockSize));
                    aMessageOut->SetBlockWiseBlockNumber(0);
                    aMessageOut->SetMoreBlocksFlag(true);
                    aMessageOut->SetBlockWiseBlockSize(mCurrentMaxBlockSize);
                    isBlock2OptionSet = true;
                    otLogInfoCoap("Start Block2 transfer");
                }

                // Set Block1 option to confirm receiving of last block
                if (option->mNumber >= OT_COAP_OPTION_BLOCK1 && !isBlock1OptionSet)
                {
                    SuccessOrExit(error = aMessageOut->AppendBlockOption(
                                      OT_COAP_OPTION_BLOCK1, mLastResponse->GetBlockWiseBlockNumber() + 1, false,
                                      mLastResponse->GetBlockWiseBlockSize()));
                    isBlock1OptionSet = true;

                    if (option->mNumber == OT_COAP_OPTION_BLOCK1)
                    {
                        continue;
                    }
                }

                iterator.GetOptionValue(optionBuf);
                SuccessOrExit(error = aMessageOut->AppendOption(option->mNumber, option->mLength, optionBuf));
            }
            else
            {
                // Initiate Block2 transfer
                if (option->mNumber > OT_COAP_OPTION_BLOCK2 && !isBlock2OptionSet)
                {
                    SuccessOrExit(
                        error = aMessageOut->AppendBlockOption(OT_COAP_OPTION_BLOCK2, 0, true, mCurrentMaxBlockSize));
                    aMessageOut->SetBlockWiseBlockNumber(0);
                    aMessageOut->SetMoreBlocksFlag(true);
                    aMessageOut->SetBlockWiseBlockSize(mCurrentMaxBlockSize);
                    isBlock2OptionSet = true;
                    otLogInfoCoap("Start Block2 transfer");
                }

                iterator.GetOptionValue(optionBuf);
                SuccessOrExit(error = aMessageOut->AppendOption(option->mNumber, option->mLength, optionBuf));
            }
            break;

        default:
            error = OT_ERROR_INVALID_ARGS;
            ExitNow();
            break;
        }

        if (optionBuf != NULL)
        {
            free(optionBuf);
            optionBuf = NULL;
        }
    }

    // If no options exist in the original message so far
    if (!isBlock1OptionSet && !isBlock2OptionSet)
    {
        switch (aMessage->GetCode())
        {
        case OT_COAP_CODE_POST:
        case OT_COAP_CODE_PUT:
            // Initiate Block1 transfer
            SuccessOrExit(error = aMessageOut->AppendBlockOption(OT_COAP_OPTION_BLOCK1, 0, true, mCurrentMaxBlockSize));
            otLogInfoCoap("Start Block1 transfer");
            break;

        case OT_COAP_CODE_CREATED:
        case OT_COAP_CODE_VALID:
        case OT_COAP_CODE_CHANGED:
        case OT_COAP_CODE_CONTENT:
            if (mHasLastBlockBeenReceived)
            {
                // Initiate Block2 transfer
                SuccessOrExit(error =
                                  aMessageOut->AppendBlockOption(OT_COAP_OPTION_BLOCK2, 0, true, mCurrentMaxBlockSize));

                // Set Block1 option to confirm receiving of last block
                SuccessOrExit(error = aMessageOut->AppendBlockOption(OT_COAP_OPTION_BLOCK1,
                                                                     mLastResponse->GetBlockWiseBlockNumber() + 1,
                                                                     false, mLastResponse->GetBlockWiseBlockSize()));
            }
            else
            {
                SuccessOrExit(error =
                                  aMessageOut->AppendBlockOption(OT_COAP_OPTION_BLOCK2, 0, true, mCurrentMaxBlockSize));
            }
            otLogInfoCoap("Start Block2 transfer");
            break;

        default:
            error = OT_ERROR_INVALID_ARGS;
            ExitNow();
            break;
        }

        aMessageOut->SetBlockWiseBlockNumber(0);
        aMessageOut->SetMoreBlocksFlag(true);
        aMessageOut->SetBlockWiseBlockSize(mCurrentMaxBlockSize);
    }

    SuccessOrExit(error = aMessageOut->SetPayloadMarker());
    SuccessOrExit(error = aMessageOut->Append(mDisassemblyMessage, 1 << (4 + mCurrentMaxBlockSize)));

    if (aMessageOut->GetType() == OT_COAP_TYPE_ACKNOWLEDGMENT)
    {
        error = CacheLastBlockResponse(aMessageOut);
    }

exit:
    if (optionBuf != NULL)
    {
        free(optionBuf);
        optionBuf = NULL;
    }

    return error;
}

otError CoapBase::FinishBlock1Transfer(Message &aMessage, Message &aMessageOut)
{
    otError        error         = OT_ERROR_NONE;
    bool           isOptionSet   = false;
    uint8_t *      optionBuf     = NULL;
    char *         payload       = NULL;
    uint16_t       payloadLength = 0;
    OptionIterator iterator;

    SuccessOrExit(error = iterator.Init(&aMessage));

    aMessageOut.Init(OT_COAP_TYPE_ACKNOWLEDGMENT, aMessage.GetCode());
    aMessageOut.SetToken(aMessage.GetToken(), aMessage.GetTokenLength());
    aMessageOut.SetMessageId(aMessage.GetMessageId());

    for (const otCoapOption *option = iterator.GetFirstOption(); option != NULL; option = iterator.GetNextOption())
    {
        VerifyOrExit((optionBuf = (uint8_t *)calloc(option->mLength, sizeof(uint8_t))) != NULL,
                     error = OT_ERROR_NO_BUFS);

        if (option->mNumber >= OT_COAP_OPTION_BLOCK1 && !isOptionSet)
        {
            // Set Block1 option to confirm receiving of last block
            SuccessOrExit(error = aMessageOut.AppendBlockOption(OT_COAP_OPTION_BLOCK1,
                                                                mLastResponse->GetBlockWiseBlockNumber() + 1, false,
                                                                mLastResponse->GetBlockWiseBlockSize()));
            isOptionSet = true;

            if (option->mNumber == OT_COAP_OPTION_BLOCK1)
            {
                continue;
            }
        }

        iterator.GetOptionValue(optionBuf);
        SuccessOrExit(error = aMessageOut.AppendOption(option->mNumber, option->mLength, optionBuf));

        if (optionBuf != NULL)
        {
            free(optionBuf);
            optionBuf = NULL;
        }
    }

    if (!isOptionSet)
    {
        SuccessOrExit(error = aMessageOut.AppendBlockOption(OT_COAP_OPTION_BLOCK1,
                                                            mLastResponse->GetBlockWiseBlockNumber() + 1, false,
                                                            mLastResponse->GetBlockWiseBlockSize()));
    }

    if (aMessage.GetLength() - aMessage.GetHeaderLength() > 0)
    {
        VerifyOrExit((payload = (char *)calloc(aMessage.GetLength() - aMessage.GetHeaderLength(), sizeof(char))) !=
                         NULL,
                     error = OT_ERROR_NO_BUFS);

        payloadLength =
            aMessage.Read(aMessage.GetHeaderLength(), aMessage.GetLength() - aMessage.GetHeaderLength(), payload);

        SuccessOrExit(error = aMessageOut.SetPayloadMarker());
        SuccessOrExit(error = aMessageOut.Append(payload, payloadLength));
    }

exit:
    if (payload != NULL)
    {
        free(payload);
    }

    if (optionBuf != NULL)
    {
        free(optionBuf);
        optionBuf = NULL;
    }

    return error;
}*/

otError CoapBase::SendNextBlock1Request(Message &               aRequest,
                                        Message &               aMessage,
                                        const Ip6::MessageInfo &aMessageInfo,
                                        const CoapMetadata &    aCoapMetadata)
{
    otError        error                                        = OT_ERROR_NONE;
    Message *      message                                      = NULL;
    bool           moreBlocks                                   = false;
    bool           isOptionSet                                  = false;
    uint8_t *      optionBuf                                    = NULL;
    uint8_t        buf[OPENTHREAD_CONFIG_COAP_MAX_BLOCK_LENGTH] = {0};
    uint16_t       bufLen                                       = OPENTHREAD_CONFIG_COAP_MAX_BLOCK_LENGTH;
    OptionIterator iterator;

    SuccessOrExit(error = iterator.Init(&aRequest));

    // Initialize next message
    VerifyOrExit((message = NewMessage()) != NULL, error = OT_ERROR_NO_BUFS);
    message->Init(OT_COAP_TYPE_CONFIRMABLE, aRequest.GetCode());

    SuccessOrExit(error = aMessage.ReadBlockOptionValues(OT_COAP_OPTION_BLOCK1));

    // Get next block
    SuccessOrExit(error = aCoapMetadata.mBlockwiseTransmitHook(
                      buf, (1 << (4 + aMessage.GetBlockWiseBlockSize())) * (aMessage.GetBlockWiseBlockNumber() + 1),
                      &bufLen, &moreBlocks));

    // Check if block length is valid
    VerifyOrExit(bufLen <= 1 << (4 + aMessage.GetBlockWiseBlockSize()), error = OT_ERROR_INVALID_ARGS);

    // Copy options from last response to next message
    for (const otCoapOption *option = iterator.GetFirstOption(); option != NULL; option = iterator.GetNextOption())
    {
        VerifyOrExit((optionBuf = (uint8_t *)calloc(option->mLength, sizeof(uint8_t))) != NULL,
                     error = OT_ERROR_NO_BUFS);

        // Check if option to copy next is higher than or equal to Block1 option
        if (option->mNumber >= OT_COAP_OPTION_BLOCK1 && !isOptionSet)
        {
            // Write Block1 option to next message
            SuccessOrExit(error =
                              message->AppendBlockOption(OT_COAP_OPTION_BLOCK1, aMessage.GetBlockWiseBlockNumber() + 1,
                                                         moreBlocks, aMessage.GetBlockWiseBlockSize()));
            message->SetBlockWiseBlockNumber(aMessage.GetBlockWiseBlockNumber() + 1);
            message->SetBlockWiseBlockSize(aMessage.GetBlockWiseBlockSize());
            message->SetMoreBlocksFlag(moreBlocks);

            isOptionSet = true;

            // If option to copy next is Block1 option, option is not copied
            if (option->mNumber == OT_COAP_OPTION_BLOCK1)
            {
                continue;
            }
        }

        // Copy option
        iterator.GetOptionValue(optionBuf);
        SuccessOrExit(error = message->AppendOption(option->mNumber, option->mLength, optionBuf));

        if (optionBuf != NULL)
        {
            free(optionBuf);
            optionBuf = NULL;
        }
    }

    message->SetMessageId(mMessageId++);
    SuccessOrExit(error = message->SetPayloadMarker());

    SuccessOrExit(error = message->Append(buf, bufLen));

    DequeueMessage(aRequest);

    otLogInfoCoap("Send Block1 Nr. %d, Size: %d bytes, More Blocks Flag: %d", message->GetBlockWiseBlockNumber(),
                  1 << (4 + message->GetBlockWiseBlockSize()), message->IsMoreBlocksFlagSet());

    SuccessOrExit(error = SendMessage(*message, aMessageInfo, aCoapMetadata.mResponseHandler,
                                      aCoapMetadata.mResponseContext, aCoapMetadata.mBlockwiseTransmitHook,
                                      aCoapMetadata.mBlockwiseReceiveHook));

exit:
    if (error != OT_ERROR_NONE && message != NULL)
    {
        message->Free();
    }

    if (optionBuf != NULL)
    {
        free(optionBuf);
        optionBuf = NULL;
    }

    return error;
}

otError CoapBase::SendNextBlock2Request(Message &               aRequest,
                                        Message &               aMessage,
                                        const Ip6::MessageInfo &aMessageInfo,
                                        const CoapMetadata &    aCoapMetadata,
                                        uint32_t                aTotalLength)
{
    otError        error                                        = OT_ERROR_NONE;
    Message *      request                                      = NULL;
    uint8_t        buf[OPENTHREAD_CONFIG_COAP_MAX_BLOCK_LENGTH] = {0};
    uint16_t       bufLen                                       = OPENTHREAD_CONFIG_COAP_MAX_BLOCK_LENGTH;
    uint8_t *      optionBuf                                    = NULL;
    OptionIterator iterator;
    bool           isOptionSet = false;

    SuccessOrExit(error = iterator.Init(&aRequest));

    SuccessOrExit(error = aMessage.ReadBlockOptionValues(OT_COAP_OPTION_BLOCK2));

    // Check payload and block length
    VerifyOrExit((aMessage.GetLength() - aMessage.GetOffset()) <=
                     (1 << (4 + (uint16_t)aMessage.GetBlockWiseBlockSize())),
                 error = OT_ERROR_NO_BUFS);

    // Read and then forward payload to receive hook function
    bufLen = aMessage.Read(aMessage.GetOffset(), aMessage.GetLength() - aMessage.GetOffset(), buf);
    SuccessOrExit(error = aCoapMetadata.mBlockwiseReceiveHook(
                      buf, (1 << (4 + (uint16_t)aMessage.GetBlockWiseBlockSize())) * aMessage.GetBlockWiseBlockNumber(),
                      bufLen, aMessage.IsMoreBlocksFlagSet(), aTotalLength));

    // CoAP Block-Wise Transfer continues
    otLogInfoCoap("Received Block2 Nr. %d , Size: %d bytes, More Blocks Flag: %d", aMessage.GetBlockWiseBlockNumber(),
                  1 << (4 + aMessage.GetBlockWiseBlockSize()), aMessage.IsMoreBlocksFlagSet());

    // Copy options from last resquest to next message
    for (const otCoapOption *option = iterator.GetFirstOption(); option != NULL; option = iterator.GetNextOption())
    {
        VerifyOrExit((optionBuf = (uint8_t *)calloc(option->mLength, sizeof(uint8_t))) != NULL,
                     error = OT_ERROR_NO_BUFS);

        // Check if option to copy next is higher than or equal to Block2 option
        if (option->mNumber >= OT_COAP_OPTION_BLOCK2 && !isOptionSet)
        {
            // Write Block2 option to next message
            SuccessOrExit(
                error = request->AppendBlockOption(OT_COAP_OPTION_BLOCK2, aMessage.GetBlockWiseBlockNumber() + 1,
                                                   aMessage.IsMoreBlocksFlagSet(), aMessage.GetBlockWiseBlockSize()));
            request->SetBlockWiseBlockNumber(aMessage.GetBlockWiseBlockNumber() + 1);
            request->SetBlockWiseBlockSize(aMessage.GetBlockWiseBlockSize());
            request->SetMoreBlocksFlag(aMessage.IsMoreBlocksFlagSet());

            isOptionSet = true;

            // If option to copy next is Block1 option, option is not copied
            if (option->mNumber == OT_COAP_OPTION_BLOCK2)
            {
                continue;
            }
        }

        // Copy option
        iterator.GetOptionValue(optionBuf);
        SuccessOrExit(error = request->AppendOption(option->mNumber, option->mLength, optionBuf));

        if (optionBuf != NULL)
        {
            free(optionBuf);
            optionBuf = NULL;
        }
    }

    request->SetMessageId(mMessageId++);

    SuccessOrExit(error = SendMessage(*request, aMessageInfo, aCoapMetadata.mResponseHandler,
                                      aCoapMetadata.mResponseContext, NULL, aCoapMetadata.mBlockwiseReceiveHook));

    otLogInfoCoap("Request Block2 Nr. %d, Size: %d bytes", request->GetBlockWiseBlockNumber(),
                  1 << (4 + request->GetBlockWiseBlockSize()));

exit:
    if (error != OT_ERROR_NONE && request != NULL)
    {
        request->Free();
    }

    return error;
}
/*
void CoapBase::FinalizeCoapBlockWiseTransaction(Message *               aLastBlock,
                                                const Ip6::MessageInfo *aMessageInfo,
                                                Message *               aRequest,
                                                const CoapMetadata *    aCoapMetadata,
                                                const char *            aUri)
{
    otError        error     = OT_ERROR_NONE;
    Message *      message   = NULL;
    uint8_t *      optionBuf = NULL;
    OptionIterator iterator;

    SuccessOrExit(error = iterator.Init(aLastBlock));

    // Reassemble message
    otLogDebgCoap("Last block received");

    VerifyOrExit((message = NewMessage()) != NULL, error = OT_ERROR_NO_BUFS);
    message->Init(aLastBlock->GetType(), aLastBlock->GetCode());
    SuccessOrExit(error = message->SetToken(aLastBlock->GetToken(), aLastBlock->GetTokenLength()));
    message->SetMessageId(aLastBlock->GetMessageId());

    for (const otCoapOption *option = iterator.GetFirstOption(); option != NULL; option = iterator.GetNextOption())
    {
        VerifyOrExit((optionBuf = (uint8_t *)calloc(option->mLength, sizeof(uint8_t))) != NULL,
                     error = OT_ERROR_NO_BUFS);

        if ((option->mNumber != OT_COAP_OPTION_BLOCK1) && (option->mNumber != OT_COAP_OPTION_BLOCK2))
        {
            iterator.GetOptionValue(optionBuf);
            SuccessOrExit(error = message->AppendOption(option->mNumber, option->mLength, optionBuf));
        }

        if (optionBuf != NULL)
        {
            free(optionBuf);
            optionBuf = NULL;
        }
    }

    SuccessOrExit(error = message->SetPayloadMarker());
    SuccessOrExit(error = message->Append(mReassemblyMessage, mReassemblyMessageLength));

    message->Finish();

    if (aUri != NULL)
    {
        // Finalize Block1 transfer
        otLogInfoCoap("Finalized Block1 transfer");

        mHasLastBlockBeenReceived = true;

        for (const Resource *resource = mResources.GetHead(); resource; resource = resource->GetNext())
        {
            if (strcmp(resource->mUriPath, aUri) == 0)
            {
                resource->HandleRequest(*message, *aMessageInfo);
                error = OT_ERROR_NONE;
                ExitNow();
            }
        }

        if (mDefaultHandler)
        {
            mDefaultHandler(mDefaultHandlerContext, message, aMessageInfo);
            error = OT_ERROR_NONE;
        }
    }

exit:
    if (optionBuf != NULL)
    {
        free(optionBuf);
        optionBuf = NULL;
    }

    if ((aRequest != NULL) && (aCoapMetadata != NULL) && (aUri == NULL))
    {
        // Finalize Block2 transfer
        otLogInfoCoap("Finalized Block2 transfer");

        FinalizeCoapTransaction(*aRequest, *aCoapMetadata, message, aMessageInfo, error);
    }

    if (error != OT_ERROR_NONE)
    {
        otLogWarnCoap("Finalizing block-wise transfer failed!");
    }
    else
    {
        CleanupBlockWiseTransfer();
    }

    if (message != NULL)
    {
        message->Free();
    }
}
*/

otError CoapBase::ProcessBlock1Request(Message &                  aMessage,
                                       const Ip6::MessageInfo &   aMessageInfo,
                                       otCoapBlockwiseReceiveHook aReceiveHook,
                                       uint32_t                   aTotalLength)
{
    otError  error                                        = OT_ERROR_NONE;
    Message *response                                     = NULL;
    uint8_t  buf[OPENTHREAD_CONFIG_COAP_MAX_BLOCK_LENGTH] = {0};
    uint16_t bufLen                                       = OPENTHREAD_CONFIG_COAP_MAX_BLOCK_LENGTH;

    SuccessOrExit(error = aMessage.ReadBlockOptionValues(OT_COAP_OPTION_BLOCK1));

    // Read and then forward payload to receive hook function
    bufLen = aMessage.Read(aMessage.GetOffset(), aMessage.GetLength() - aMessage.GetOffset(), buf);
    SuccessOrExit(error = aReceiveHook(buf,
                                       (1 << (4 + static_cast<uint32_t>(aMessage.GetBlockWiseBlockSize()))) *
                                           aMessage.GetBlockWiseBlockNumber(),
                                       bufLen, aMessage.IsMoreBlocksFlagSet(), aTotalLength));

    if (aMessage.IsMoreBlocksFlagSet())
    {
        // Set up next response
        VerifyOrExit((response = NewMessage()) != NULL, error = OT_ERROR_FAILED);
        response->Init(OT_COAP_TYPE_ACKNOWLEDGMENT, OT_COAP_CODE_CONTINUE);
        response->SetMessageId(aMessage.GetMessageId());
        response->SetToken(aMessage.GetToken(), aMessage.GetTokenLength());

        response->SetBlockWiseBlockNumber(aMessage.GetBlockWiseBlockNumber());
        response->SetMoreBlocksFlag(aMessage.IsMoreBlocksFlagSet());
        response->SetBlockWiseBlockSize(aMessage.GetBlockWiseBlockSize());

        SuccessOrExit(error = response->AppendBlockOption(OT_COAP_OPTION_BLOCK1, response->GetBlockWiseBlockNumber(),
                                                          response->IsMoreBlocksFlagSet(),
                                                          response->GetBlockWiseBlockSize()));

        SuccessOrExit(error = SendMessage(*response, aMessageInfo));

        otLogInfoCoap("Acknowledge Block1 Nr. %d, Size: %d bytes", response->GetBlockWiseBlockNumber(),
                      1 << (4 + response->GetBlockWiseBlockSize()));

        error = OT_ERROR_BUSY;
    }
    else
    {
        error = OT_ERROR_NONE;
    }

exit:
    if (error != OT_ERROR_NONE && error != OT_ERROR_BUSY && response != NULL)
    {
        response->Free();
    }

    return error;
}

otError CoapBase::ProcessBlock2Request(Message &                   aMessage,
                                       const Ip6::MessageInfo &    aMessageInfo,
                                       otCoapBlockwiseTransmitHook aTransmitHook)
{
    otError        error                                        = OT_ERROR_NONE;
    Message *      response                                     = NULL;
    uint8_t        buf[OPENTHREAD_CONFIG_COAP_MAX_BLOCK_LENGTH] = {0};
    uint16_t       bufLen                                       = 0;
    bool           moreBlocks                                   = false;
    uint8_t *      optionBuf                                    = NULL;
    OptionIterator iterator;

    SuccessOrExit(error = aMessage.ReadBlockOptionValues(OT_COAP_OPTION_BLOCK2));
    bufLen = 1 << (4 + aMessage.GetBlockWiseBlockSize());

    otLogInfoCoap("Request for Block2 Nr. %d, Size: %d bytes received", aMessage.GetBlockWiseBlockNumber(),
                  1 << (4 + aMessage.GetBlockWiseBlockSize()));

    // Set up next response
    VerifyOrExit((response = NewMessage()) != NULL, error = OT_ERROR_NO_BUFS);
    response->Init(OT_COAP_TYPE_ACKNOWLEDGMENT, OT_COAP_CODE_CONTENT);
    response->SetMessageId(aMessage.GetMessageId());

    SuccessOrExit(
        error = aTransmitHook(buf, (1 << (4 + aMessage.GetBlockWiseBlockSize())) * aMessage.GetBlockWiseBlockNumber(),
                              &bufLen, &moreBlocks));

    response->SetMoreBlocksFlag(moreBlocks);
    if (moreBlocks)
    {
        switch (bufLen)
        {
        case 1024:
            response->SetBlockWiseBlockSize(OT_COAP_OPTION_BLOCK_SZX_1024);
            break;
        case 512:
            response->SetBlockWiseBlockSize(OT_COAP_OPTION_BLOCK_SZX_512);
            break;
        case 128:
            response->SetBlockWiseBlockSize(OT_COAP_OPTION_BLOCK_SZX_128);
            break;
        case 64:
            response->SetBlockWiseBlockSize(OT_COAP_OPTION_BLOCK_SZX_64);
            break;
        case 32:
            response->SetBlockWiseBlockSize(OT_COAP_OPTION_BLOCK_SZX_32);
            break;
        case 16:
            response->SetBlockWiseBlockSize(OT_COAP_OPTION_BLOCK_SZX_16);
            break;
        default:
            error = OT_ERROR_INVALID_ARGS;
            ExitNow();
            break;
        }

        response->SetBlockWiseBlockNumber(
            ((1 << (4 + aMessage.GetBlockWiseBlockSize())) * aMessage.GetBlockWiseBlockNumber()) /
            (1 << (4 + response->GetBlockWiseBlockSize())));
    }
    else
    {
        // Verify that buffer length is not larger than requested block size
        VerifyOrExit(bufLen < 1 << (4 + aMessage.GetBlockWiseBlockSize()), error = OT_ERROR_INVALID_ARGS);
        response->SetBlockWiseBlockSize(aMessage.GetBlockWiseBlockSize());
    }

    // Copy options from last response
    SuccessOrExit(error = iterator.Init(mLastResponse));

    for (const otCoapOption *option = iterator.GetFirstOption(); option != NULL; option = iterator.GetNextOption())
    {
        VerifyOrExit((optionBuf = (uint8_t *)calloc(option->mLength, sizeof(uint8_t))) != NULL,
                     error = OT_ERROR_NO_BUFS);

        if (option->mNumber != OT_COAP_OPTION_BLOCK2)
        {
            iterator.GetOptionValue(optionBuf);
            SuccessOrExit(error = response->AppendOption(option->mNumber, option->mLength, optionBuf));
        }
        else
        {
            SuccessOrExit(error = response->AppendBlockOption(
                              OT_COAP_OPTION_BLOCK2, response->GetBlockWiseBlockNumber(),
                              response->IsMoreBlocksFlagSet(), response->GetBlockWiseBlockSize()));
        }

        if (optionBuf != NULL)
        {
            free(optionBuf);
            optionBuf = NULL;
        }
    }

    SuccessOrExit(error = response->SetPayloadMarker());
    SuccessOrExit(error = response->Append(buf, bufLen));

    SuccessOrExit(error = CacheLastBlockResponse(response));

    SuccessOrExit(error = SendMessage(*response, aMessageInfo));

    otLogInfoCoap("Send Block2 Nr. %d, Size: %d bytes, More Blocks Flag %d", response->GetBlockWiseBlockNumber(),
                  1 << (4 + response->GetBlockWiseBlockSize()), response->IsMoreBlocksFlagSet());

exit:
    if (error != OT_ERROR_NONE && response != NULL)
    {
        response->Free();
    }

    if (optionBuf != NULL)
    {
        free(optionBuf);
        optionBuf = NULL;
    }

    return error;
}
//#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

otError CoapBase::SendCopy(const Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    otError  error;
    Message *messageCopy = NULL;

    // Create a message copy for lower layers.
    VerifyOrExit((messageCopy = aMessage.Clone(aMessage.GetLength() - sizeof(CoapMetadata))) != NULL,
                 error = OT_ERROR_NO_BUFS);

    // Send the copy.
    SuccessOrExit(error = Send(*messageCopy, aMessageInfo));

exit:

    if (error != OT_ERROR_NONE && messageCopy != NULL)
    {
        messageCopy->Free();
    }

    return error;
}

Message *CoapBase::FindRelatedRequest(const Message &         aResponse,
                                      const Ip6::MessageInfo &aMessageInfo,
                                      CoapMetadata &          aCoapMetadata)
{
    Message *message = static_cast<Message *>(mPendingRequests.GetHead());

    while (message != NULL)
    {
        aCoapMetadata.ReadFrom(*message);

        if (((aCoapMetadata.mDestinationAddress == aMessageInfo.GetPeerAddr()) ||
             aCoapMetadata.mDestinationAddress.IsMulticast() ||
             aCoapMetadata.mDestinationAddress.IsAnycastRoutingLocator()) &&
            (aCoapMetadata.mDestinationPort == aMessageInfo.GetPeerPort()))
        {
            switch (aResponse.GetType())
            {
            case OT_COAP_TYPE_RESET:
            case OT_COAP_TYPE_ACKNOWLEDGMENT:
                if (aResponse.GetMessageId() == message->GetMessageId())
                {
                    ExitNow();
                }

                break;

            case OT_COAP_TYPE_CONFIRMABLE:
            case OT_COAP_TYPE_NON_CONFIRMABLE:
                if (aResponse.IsTokenEqual(*message))
                {
                    ExitNow();
                }

                break;
            }
        }

        message = static_cast<Message *>(message->GetNext());
    }

exit:
    return message;
}

void CoapBase::Receive(ot::Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    Message &message = static_cast<Message &>(aMessage);

    if (message.ParseHeader() != OT_ERROR_NONE)
    {
        otLogDebgCoap("Failed to parse CoAP header");

        if (!aMessageInfo.GetSockAddr().IsMulticast() && message.IsConfirmable())
        {
            SendReset(message, aMessageInfo);
        }
    }
    else if (message.IsRequest())
    {
        ProcessReceivedRequest(message, aMessageInfo);
    }
    else
    {
        ProcessReceivedResponse(message, aMessageInfo);
    }
}

void CoapBase::ProcessReceivedResponse(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    CoapMetadata coapMetadata;
    Message *    request = NULL;
    otError      error   = OT_ERROR_NONE;
    //#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    uint8_t        blockOptionType    = 0;
    uint32_t       totalTransfereSize = 0;
    OptionIterator iterator;
    //#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

    VerifyOrExit((request = FindRelatedRequest(aMessage, aMessageInfo, coapMetadata)) != NULL);

    switch (aMessage.GetType())
    {
    case OT_COAP_TYPE_RESET:
        //#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
        if (mIsBlockWiseTransferActive)
        {
            mIsBlockWiseTransferActive = false;
        }
        //#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
        if (aMessage.IsEmpty())
        {
            FinalizeCoapTransaction(*request, coapMetadata, NULL, NULL, OT_ERROR_ABORT);
        }

        // Silently ignore non-empty reset messages (RFC 7252, p. 4.2).
        break;

    case OT_COAP_TYPE_ACKNOWLEDGMENT:
        if (aMessage.IsEmpty())
        {
            // Empty acknowledgment.
            if (coapMetadata.mConfirmable)
            {
                coapMetadata.mAcknowledged = true;
                coapMetadata.UpdateIn(*request);
            }

            // Remove the message if response is not expected, otherwise await response.
            if (coapMetadata.mResponseHandler == NULL)
            {
                DequeueMessage(*request);
            }
        }
        else if (aMessage.IsResponse() && aMessage.IsTokenEqual(*request))
        {
#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
            if (coapMetadata.mBlockwiseTransmitHook != NULL || coapMetadata.mBlockwiseReceiveHook != NULL)
            {
                // Search for CoAP Block-Wise Option [RFC7959]
                SuccessOrExit(error = iterator.Init(&aMessage));
                for (const otCoapOption *option = iterator.GetFirstOption(); option != NULL;
                     option                     = iterator.GetNextOption())
                {
                    switch (option->mNumber)
                    {
                    case OT_COAP_OPTION_BLOCK1:
                        blockOptionType += 1;
                        break;

                    case OT_COAP_OPTION_BLOCK2:
                        blockOptionType += 2;
                        break;

                    case OT_COAP_OPTION_SIZE2:
                        // ToDo: wait for method to read uint option values
                        totalTransfereSize = 0;
                        break;

                    default:
                        break;
                    }
                }
            }
            switch (blockOptionType)
            {
            case 0:
                // Piggybacked response.
                FinalizeCoapTransaction(*request, coapMetadata, &aMessage, &aMessageInfo, OT_ERROR_NONE);
                break;
            case 1: // Block1 option
                if (aMessage.GetCode() == OT_COAP_CODE_CONTINUE && coapMetadata.mBlockwiseTransmitHook != NULL)
                {
                    error = SendNextBlock1Request(*request, aMessage, aMessageInfo, coapMetadata);
                }

                if (aMessage.GetCode() != OT_COAP_CODE_CONTINUE || coapMetadata.mBlockwiseTransmitHook == NULL ||
                    error != OT_ERROR_NONE)
                {
                    FinalizeCoapTransaction(*request, coapMetadata, &aMessage, &aMessageInfo, error);
                }
                break;
            case 2: // Block2 option
                if (aMessage.GetCode() < OT_COAP_CODE_BAD_REQUEST && coapMetadata.mBlockwiseReceiveHook != NULL)
                {
                    error = SendNextBlock2Request(*request, aMessage, aMessageInfo, coapMetadata, totalTransfereSize);
                }

                if (aMessage.GetCode() >= OT_COAP_CODE_BAD_REQUEST || coapMetadata.mBlockwiseReceiveHook == NULL ||
                    error != OT_ERROR_NONE)
                {
                    FinalizeCoapTransaction(*request, coapMetadata, &aMessage, &aMessageInfo, error);
                }
                break;
            case 3: // Block1 & Block2 option
                // ToDo:
                if (aMessage.GetCode() < OT_COAP_CODE_BAD_REQUEST && coapMetadata.mBlockwiseReceiveHook != NULL)
                {
                    error = SendNextBlock2Request(*request, aMessage, aMessageInfo, coapMetadata, totalTransfereSize);
                }

                FinalizeCoapTransaction(*request, coapMetadata, &aMessage, &aMessageInfo, error);
                break;
            default:
                error = OT_ERROR_ABORT;
                FinalizeCoapTransaction(*request, coapMetadata, &aMessage, &aMessageInfo, error);
                break;
            }
#else
            // Piggybacked response.
            FinalizeCoapTransaction(*request, coapMetadata, &aMessage, &aMessageInfo, OT_ERROR_NONE);
#endif
        }

        // Silently ignore acknowledgments carrying requests (RFC 7252, p. 4.2)
        // or with no token match (RFC 7252, p. 5.3.2)
        break;

    case OT_COAP_TYPE_CONFIRMABLE:
        // Send empty ACK if it is a CON message.
        SendAck(aMessage, aMessageInfo);
        FinalizeCoapTransaction(*request, coapMetadata, &aMessage, &aMessageInfo, OT_ERROR_NONE);
        break;

    case OT_COAP_TYPE_NON_CONFIRMABLE:
        // Separate response.

        if (coapMetadata.mDestinationAddress.IsMulticast() && coapMetadata.mResponseHandler != NULL)
        {
            // If multicast non-confirmable request, allow multiple responses
            coapMetadata.mResponseHandler(coapMetadata.mResponseContext, &aMessage, &aMessageInfo, OT_ERROR_NONE);
        }
        else
        {
            FinalizeCoapTransaction(*request, coapMetadata, &aMessage, &aMessageInfo, OT_ERROR_NONE);
        }

        break;
    }

exit:

    if (error == OT_ERROR_NONE && request == NULL)
    {
        if (aMessage.IsConfirmable() || aMessage.IsNonConfirmable())
        {
            // Successfully parsed a header but no matching request was found - reject the message by sending reset.
            SendReset(aMessage, aMessageInfo);
        }
    }
}

void CoapBase::ProcessReceivedRequest(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    char           uriPath[Resource::kMaxReceivedUriPath];
    char *         curUriPath     = uriPath;
    Message *      cachedResponse = NULL;
    otError        error          = OT_ERROR_NOT_FOUND;
    OptionIterator iterator;
    //#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    uint8_t  blockOptionType    = 0;
    uint32_t totalTransfereSize = 0;
    //#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

    if (mInterceptor != NULL)
    {
        SuccessOrExit(error = mInterceptor(aMessage, aMessageInfo, mContext));
    }

    switch (mResponsesQueue.GetMatchedResponseCopy(aMessage, aMessageInfo, &cachedResponse))
    {
    case OT_ERROR_NONE:
        cachedResponse->Finish();
        error = Send(*cachedResponse, aMessageInfo);
        // fall through
        ;

    case OT_ERROR_NO_BUFS:
        ExitNow();

    case OT_ERROR_NOT_FOUND:
    default:
        break;
    }

    SuccessOrExit(error = iterator.Init(&aMessage));
    for (const otCoapOption *option = iterator.GetFirstOption(); option != NULL; option = iterator.GetNextOption())
    {
        switch (option->mNumber)
        {
        case OT_COAP_OPTION_URI_PATH:
            if (curUriPath != uriPath)
            {
                *curUriPath++ = '/';
            }

            VerifyOrExit(option->mLength < sizeof(uriPath) - static_cast<size_t>(curUriPath + 1 - uriPath));

            iterator.GetOptionValue(curUriPath);
            curUriPath += option->mLength;
            break;

#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
        case OT_COAP_OPTION_BLOCK1:
            blockOptionType += 1;
            break;

        case OT_COAP_OPTION_BLOCK2:
            blockOptionType += 2;
            break;

        case OT_COAP_OPTION_SIZE1:
            // ToDo: wait for method to read uint option values
            totalTransfereSize = 0;
            break;
#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

        default:
            break;
        }
    }

    curUriPath[0] = '\0';

#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    for (const Resource *resource = mResources.GetHead(); resource; resource = resource->GetNext())
    {
        if (strcmp(resource->mUriPath, uriPath) == 0)
        {
            if ((resource->mReceiveHook != NULL || resource->mTransmitHook != NULL) && blockOptionType != 0)
            {
                switch (blockOptionType)
                {
                case 1:
                    if (resource->mReceiveHook != NULL)
                    {
                        switch (
                            ProcessBlock1Request(aMessage, aMessageInfo, resource->mReceiveHook, totalTransfereSize))
                        {
                        case OT_ERROR_NONE:
                            resource->HandleRequest(aMessage, aMessageInfo);
                            // Fall through
                        case OT_ERROR_BUSY:
                            error = OT_ERROR_NONE;
                            break;
                        case OT_ERROR_NO_BUFS:
                            SendHeaderResponse(OT_COAP_CODE_REQUEST_TOO_LARGE, aMessage, aMessageInfo);
                            error = OT_ERROR_DROP;
                            break;
                        case OT_ERROR_NO_FRAME_RECEIVED:
                            SendHeaderResponse(OT_COAP_CODE_REQUEST_INCOMPLETE, aMessage, aMessageInfo);
                            error = OT_ERROR_DROP;
                            break;
                        default:
                            SendHeaderResponse(OT_COAP_CODE_INTERNAL_ERROR, aMessage, aMessageInfo);
                            error = OT_ERROR_DROP;
                            break;
                        }
                    }
                    break;
                case 2:
                    if (resource->mTransmitHook != NULL)
                    {
                        if ((error = ProcessBlock2Request(aMessage, aMessageInfo, resource->mTransmitHook)) !=
                            OT_ERROR_NONE)
                        {
                            SendHeaderResponse(OT_COAP_CODE_INTERNAL_ERROR, aMessage, aMessageInfo);
                            error = OT_ERROR_DROP;
                        }
                    }
                    break;
                }
                ExitNow();
            }
            else
            {
                resource->HandleRequest(aMessage, aMessageInfo);
                error = OT_ERROR_NONE;
                ExitNow();
            }
        }
    }
#else  // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
    for (const Resource *resource = mResources.GetHead(); resource; resource = resource->GetNext())
    {
        if (strcmp(resource->mUriPath, uriPath) == 0)
        {
            resource->HandleRequest(aMessage, aMessageInfo);
            error = OT_ERROR_NONE;
            ExitNow();
        }
    }
#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

    if (mDefaultHandler)
    {
        mDefaultHandler(mDefaultHandlerContext, &aMessage, &aMessageInfo);
        error = OT_ERROR_NONE;
    }

exit:

    if (error != OT_ERROR_NONE)
    {
        otLogInfoCoap("Failed to process request: %s", otThreadErrorToString(error));

        if (error == OT_ERROR_NOT_FOUND && !aMessageInfo.GetSockAddr().IsMulticast())
        {
            SendNotFound(aMessage, aMessageInfo);
        }

        if (cachedResponse != NULL)
        {
            cachedResponse->Free();
        }
    }
}

#if OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
CoapMetadata::CoapMetadata(bool                        aConfirmable,
                           const Ip6::MessageInfo &    aMessageInfo,
                           otCoapResponseHandler       aHandler,
                           void *                      aContext,
                           otCoapBlockwiseReceiveHook  aReceiveHook,
                           otCoapBlockwiseTransmitHook aTransmitHook)
{
    mSourceAddress         = aMessageInfo.GetSockAddr();
    mDestinationPort       = aMessageInfo.GetPeerPort();
    mDestinationAddress    = aMessageInfo.GetPeerAddr();
    mResponseHandler       = aHandler;
    mResponseContext       = aContext;
    mBlockwiseReceiveHook  = aReceiveHook;
    mBlockwiseTransmitHook = aTransmitHook;
    mRetransmissionCount   = 0;
    mRetransmissionTimeout = Time::SecToMsec(kAckTimeout);
    mRetransmissionTimeout += Random::NonCrypto::GetUint32InRange(
        0, Time::SecToMsec(kAckTimeout) * kAckRandomFactorNumerator / kAckRandomFactorDenominator -
               Time::SecToMsec(kAckTimeout) + 1);

    if (aConfirmable)
    {
        // Set next retransmission timeout.
        mNextTimerShot = TimerMilli::GetNow() + mRetransmissionTimeout;
    }
    else
    {
        // Set overall response timeout.
        mNextTimerShot = TimerMilli::GetNow() + Time::SecToMsec(kMaxTransmitWait);
    }

    mAcknowledged = false;
    mConfirmable  = aConfirmable;
}
#else  // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE
CoapMetadata::CoapMetadata(bool                    aConfirmable,
                           const Ip6::MessageInfo &aMessageInfo,
                           otCoapResponseHandler   aHandler,
                           void *                  aContext,
                           const CoapTxParameters &aTxParameters)
{
    mSourceAddress            = aMessageInfo.GetSockAddr();
    mDestinationPort          = aMessageInfo.GetPeerPort();
    mDestinationAddress       = aMessageInfo.GetPeerAddr();
    mResponseHandler          = aHandler;
    mResponseContext          = aContext;
    mRetransmissionsRemaining = aTxParameters.mMaxRetransmit;
    mRetransmissionTimeout    = aTxParameters.CalculateInitialRetransmissionTimeout();

    if (aConfirmable)
    {
        // Set next retransmission timeout.
        mNextTimerShot = TimerMilli::GetNow() + mRetransmissionTimeout;
    }
    else
    {
        // Set overall response timeout.
        mNextTimerShot = TimerMilli::GetNow() + aTxParameters.CalculateMaxTransmitWait();
    }

    mAcknowledged = false;
    mConfirmable  = aConfirmable;
}
#endif // OPENTHREAD_CONFIG_COAP_BLOCKWISE_TRANSFER_ENABLE

ResponsesQueue::ResponsesQueue(Instance &aInstance)
    : mQueue()
    , mTimer(aInstance, &ResponsesQueue::HandleTimer, this)
{
}

otError ResponsesQueue::GetMatchedResponseCopy(const Message &         aRequest,
                                               const Ip6::MessageInfo &aMessageInfo,
                                               Message **              aResponse)
{
    otError        error = OT_ERROR_NONE;
    const Message *cacheResponse;

    cacheResponse = FindMatchedResponse(aRequest, aMessageInfo);
    VerifyOrExit(cacheResponse != NULL, error = OT_ERROR_NOT_FOUND);

    *aResponse = cacheResponse->Clone(cacheResponse->GetLength() - sizeof(EnqueuedResponseHeader));
    VerifyOrExit(*aResponse != NULL, error = OT_ERROR_NO_BUFS);

exit:
    return error;
}

const Message *ResponsesQueue::FindMatchedResponse(const Message &aRequest, const Ip6::MessageInfo &aMessageInfo) const
{
    Message *matchedResponse = NULL;

    for (Message *message = static_cast<Message *>(mQueue.GetHead()); message != NULL;
         message          = static_cast<Message *>(message->GetNext()))
    {
        EnqueuedResponseHeader enqueuedResponseHeader;
        Ip6::MessageInfo       messageInfo;

        enqueuedResponseHeader.ReadFrom(*message);
        messageInfo = enqueuedResponseHeader.GetMessageInfo();

        // Check source endpoint
        if (messageInfo.GetPeerPort() != aMessageInfo.GetPeerPort())
        {
            continue;
        }

        if (messageInfo.GetPeerAddr() != aMessageInfo.GetPeerAddr())
        {
            continue;
        }

        // Check Message Id
        if (message->GetMessageId() != aRequest.GetMessageId())
        {
            continue;
        }

        ExitNow(matchedResponse = message);
    }

exit:
    return matchedResponse;
}

void ResponsesQueue::EnqueueResponse(Message &               aMessage,
                                     const Ip6::MessageInfo &aMessageInfo,
                                     const CoapTxParameters &aTxParameters)
{
    otError                error        = OT_ERROR_NONE;
    Message *              responseCopy = NULL;
    uint16_t               messageCount;
    uint16_t               bufferCount;
    uint32_t               exchangeLifetime = aTxParameters.CalculateExchangeLifetime();
    TimeMilli              dequeueTime      = TimerMilli::GetNow() + exchangeLifetime;
    EnqueuedResponseHeader enqueuedResponseHeader(dequeueTime, aMessageInfo);

    // return success if matched response already exists in the cache
    VerifyOrExit(FindMatchedResponse(aMessage, aMessageInfo) == NULL);

    mQueue.GetInfo(messageCount, bufferCount);

    if (messageCount >= kMaxCachedResponses)
    {
        DequeueOldestResponse();
    }

    VerifyOrExit((responseCopy = aMessage.Clone()) != NULL);

    SuccessOrExit(error = enqueuedResponseHeader.AppendTo(*responseCopy));
    mQueue.Enqueue(*responseCopy);

    if (!mTimer.IsRunning())
    {
        mTimer.Start(exchangeLifetime);
    }

exit:

    if (error != OT_ERROR_NONE && responseCopy != NULL)
    {
        responseCopy->Free();
    }

    return;
}

void ResponsesQueue::DequeueOldestResponse(void)
{
    Message *message;

    VerifyOrExit((message = static_cast<Message *>(mQueue.GetHead())) != NULL);
    DequeueResponse(*message);

exit:
    return;
}

void ResponsesQueue::DequeueAllResponses(void)
{
    Message *message;

    while ((message = static_cast<Message *>(mQueue.GetHead())) != NULL)
    {
        DequeueResponse(*message);
    }
}

void ResponsesQueue::HandleTimer(Timer &aTimer)
{
    static_cast<ResponsesQueue *>(static_cast<TimerMilliContext &>(aTimer).GetContext())->HandleTimer();
}

void ResponsesQueue::HandleTimer(void)
{
    Message *              message;
    EnqueuedResponseHeader enqueuedResponseHeader;

    while ((message = static_cast<Message *>(mQueue.GetHead())) != NULL)
    {
        enqueuedResponseHeader.ReadFrom(*message);

        if (TimerMilli::GetNow() >= enqueuedResponseHeader.mDequeueTime)
        {
            DequeueResponse(*message);
        }
        else
        {
            mTimer.Start(enqueuedResponseHeader.GetRemainingTime());
            break;
        }
    }
}

uint32_t EnqueuedResponseHeader::GetRemainingTime(void) const
{
    TimeMilli now           = TimerMilli::GetNow();
    uint32_t  remainingTime = 0;

    if (mDequeueTime > now)
    {
        remainingTime = mDequeueTime - now;
    }

    return remainingTime;
}

uint32_t CoapTxParameters::CalculateInitialRetransmissionTimeout(void) const
{
    return Random::NonCrypto::GetUint32InRange(
        mAckTimeout, mAckTimeout * mAckRandomFactorNumerator / mAckRandomFactorDenominator + 1);
}

uint32_t CoapTxParameters::CalculateExchangeLifetime(void) const
{
    uint32_t maxTransmitSpan = static_cast<uint32_t>(mAckTimeout * ((1ULL << mMaxRetransmit) - 1) *
                                                     mAckRandomFactorNumerator / mAckRandomFactorDenominator);
    uint32_t processingDelay = mAckTimeout;
    return maxTransmitSpan + 2 * kDefaultMaxLatency + processingDelay;
}

uint32_t CoapTxParameters::CalculateMaxTransmitWait(void) const
{
    return static_cast<uint32_t>(mAckTimeout * ((2ULL << mMaxRetransmit) - 1) * mAckRandomFactorNumerator /
                                 mAckRandomFactorDenominator);
}

const otCoapTxParameters CoapTxParameters::kDefaultTxParameters = {
    kDefaultAckTimeout,
    kDefaultAckRandomFactorNumerator,
    kDefaultAckRandomFactorDenominator,
    kDefaultMaxRetransmit,
};

Coap::Coap(Instance &aInstance)
    : CoapBase(aInstance, &Coap::Send)
    , mSocket(aInstance.Get<Ip6::Udp>())
{
}

otError Coap::Start(uint16_t aPort)
{
    otError       error;
    Ip6::SockAddr sockaddr;

    sockaddr.mPort = aPort;
    SuccessOrExit(error = mSocket.Open(&Coap::HandleUdpReceive, this));
    VerifyOrExit((error = mSocket.Bind(sockaddr)) == OT_ERROR_NONE, mSocket.Close());

exit:
    return error;
}

otError Coap::Stop(void)
{
    otError error;

    SuccessOrExit(error = mSocket.Close());
    ClearRequestsAndResponses();

exit:
    return error;
}

void Coap::HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    static_cast<Coap *>(aContext)->Receive(*static_cast<Message *>(aMessage),
                                           *static_cast<const Ip6::MessageInfo *>(aMessageInfo));
}

otError Coap::Send(ot::Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    return mSocket.IsBound() ? mSocket.SendTo(aMessage, aMessageInfo) : OT_ERROR_INVALID_STATE;
}

} // namespace Coap
} // namespace ot
