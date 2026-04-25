/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sensorbasicdatachannel_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "message_parcel.h"
#include "securec.h"

#include "sensor_basic_data_channel.h"
#include "sensor_data_event.h"

namespace OHOS {
namespace Sensors {
namespace {
constexpr size_t U32_AT_SIZE = 4;
} // namespace

template<class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    size_t objectSize = sizeof(object);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

static void RecvCallback(int32_t length)
{
    // no-op callback for ReceiveData
}

bool SensorBasicDataChannelFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;

    float sensorValue = 0.0f;
    startPos += GetObject<float>(sensorValue, data + startPos, size - startPos);
    int32_t sensorType = 0;
    startPos += GetObject<int32_t>(sensorType, data + startPos, size - startPos);

    // ===== 1. CreateSensorBasicChannel (socket pair) =====
    {
        sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
        if (channel == nullptr) {
            return false;
        }
        int32_t ret = channel->CreateSensorBasicChannel();
        if (ret != 0) {
            return true;  // socket creation may fail in fuzz env, that's ok
        }

        // GetSendDataFd / GetReceiveDataFd
        (void)channel->GetSendDataFd();
        (void)channel->GetReceiveDataFd();

        // GetSensorStatus / SetSensorStatus
        channel->SetSensorStatus(true);
        (void)channel->GetSensorStatus();
        channel->SetSensorStatus(false);
        (void)channel->GetSensorStatus();

        // SetPackageName / GetPackageName
        channel->SetPackageName("testPackage");
        (void)channel->GetPackageName();
        channel->SetPackageName("");
        (void)channel->GetPackageName();

        // SetUserId / GetUserId
        channel->SetUserId(100);
        (void)channel->GetUserId();

        // SetAccessTokenId / GetAccessTokenId
        channel->SetAccessTokenId("12345");
        (void)channel->GetAccessTokenId();
        channel->SetAccessTokenId("");
        (void)channel->GetAccessTokenId();

        // GetDataCacheBuf
        (void)channel->GetDataCacheBuf();

        // ===== 2. SendData =====
        {
            SensorData sensorData;
            (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
            sensorData.sensorTypeId = sensorType;
            sensorData.dataLen = sizeof(float);
            (void)memcpy_s(sensorData.data, sizeof(sensorData.data), &sensorValue, sizeof(float));
            channel->SetSensorStatus(true);
            channel->SendData(&sensorData, sizeof(sensorData));
        }
        // Send multiple SensorData
        {
            SensorData events[3];
            for (int i = 0; i < 3; i++) {
                (void)memset_s(&events[i], sizeof(SensorData), 0, sizeof(SensorData));
                events[i].sensorTypeId = sensorType + i;
                events[i].dataLen = sizeof(float);
                float val = sensorValue + static_cast<float>(i);
                (void)memcpy_s(events[i].data, sizeof(events[i].data), &val, sizeof(float));
            }
            channel->SendData(events, sizeof(events));
        }
        // SendData with nullptr
        {
            channel->SendData(nullptr, sizeof(SensorData));
        }
        // SendData with zero size
        {
            SensorData sensorData;
            (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
            channel->SendData(&sensorData, 0);
        }

        // ===== 3. ReceiveData =====
        {
            // First send some data, then receive
            SensorData sensorData;
            (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
            sensorData.sensorTypeId = sensorType;
            sensorData.dataLen = sizeof(float);
            (void)memcpy_s(sensorData.data, sizeof(sensorData.data), &sensorValue, sizeof(float));
            channel->SendData(&sensorData, sizeof(sensorData));

            // Now try to receive
            char recvBuf[4096] = {0};
            channel->ReceiveData(RecvCallback, recvBuf, sizeof(recvBuf));
        }
        // ReceiveData with nullptr callback
        {
            char recvBuf[1024] = {0};
            channel->ReceiveData(nullptr, recvBuf, sizeof(recvBuf));
        }
        // ReceiveData with nullptr vaddr
        {
            channel->ReceiveData(RecvCallback, nullptr, 1024);
        }

        // ===== 4. SendToBinder =====
        {
            MessageParcel parcel;
            channel->SendToBinder(parcel);
        }

        // ===== 5. CloseSendFd =====
        {
            channel->CloseSendFd();
            // After closing, SendData should fail
            SensorData sensorData;
            (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
            channel->SendData(&sensorData, sizeof(sensorData));
        }

        // ===== 6. DestroySensorBasicChannel =====
        channel->DestroySensorBasicChannel();
        // Double destroy should be safe
        channel->DestroySensorBasicChannel();
    }

    // ===== 7. CreateSensorBasicChannel from MessageParcel =====
    {
        // Create a channel with socket pair, write fd to parcel, then create another from parcel
        sptr<SensorBasicDataChannel> srcChannel = new (std::nothrow) SensorBasicDataChannel();
        if (srcChannel != nullptr) {
            if (srcChannel->CreateSensorBasicChannel() == 0) {
                MessageParcel parcel;
                srcChannel->SendToBinder(parcel);

                sptr<SensorBasicDataChannel> dstChannel = new (std::nothrow) SensorBasicDataChannel();
                if (dstChannel != nullptr) {
                    dstChannel->CreateSensorBasicChannel(parcel);
                    dstChannel->DestroySensorBasicChannel();
                }
            }
            srcChannel->DestroySensorBasicChannel();
        }
    }

    // ===== 8. CreateSensorBasicChannelBySendFd =====
    {
        sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
        if (channel != nullptr) {
            // Invalid fd
            channel->CreateSensorBasicChannelBySendFd(-1);
            channel->DestroySensorBasicChannel();
        }
    }
    {
        // Valid fd from another channel
        sptr<SensorBasicDataChannel> srcChannel = new (std::nothrow) SensorBasicDataChannel();
        if (srcChannel != nullptr && srcChannel->CreateSensorBasicChannel() == 0) {
            int32_t fd = srcChannel->GetSendDataFd();
            sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
            if (channel != nullptr) {
                // Note: CreateSensorBasicChannelBySendFd takes ownership, so don't destroy srcChannel's sendFd
                // This tests the duplicate path where sendFd_ != -1
                channel->CreateSensorBasicChannelBySendFd(fd);
                // Calling again should hit "Already create socketpair" path
                channel->CreateSensorBasicChannelBySendFd(fd + 1);
            }
            // Don't destroy srcChannel here as fd is shared
        }
    }

    // ===== 9. Constructor default state =====
    {
        sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
        if (channel != nullptr) {
            // Default state checks
            (void)channel->GetSensorStatus();
            (void)channel->GetPackageName();
            (void)channel->GetUserId();
            (void)channel->GetAccessTokenId();
            (void)channel->GetDataCacheBuf();
            (void)channel->GetSendDataFd();
            (void)channel->GetReceiveDataFd();

            // SendData on uninitialized channel (sendFd_ = -1)
            SensorData sensorData;
            (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
            channel->SendData(&sensorData, sizeof(sensorData));

            // SendToBinder on uninitialized channel
            MessageParcel parcel;
            channel->SendToBinder(parcel);
        }
    }

    return true;
}
}  // namespace Sensors
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < OHOS::Sensors::U32_AT_SIZE) {
        return 0;
    }
    OHOS::Sensors::SensorBasicDataChannelFuzzTest(data, size);
    return 0;
}
