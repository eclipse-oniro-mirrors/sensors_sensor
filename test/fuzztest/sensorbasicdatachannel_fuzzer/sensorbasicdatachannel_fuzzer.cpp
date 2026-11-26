/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t NEXT_SENSOR_OFFSET = 1;
constexpr int32_t INVALID_FD = -1;
constexpr size_t BATCH_EVENT_COUNT = 3;
constexpr size_t LARGE_RECEIVE_BUFFER_SIZE = 4096;
constexpr size_t SMALL_RECEIVE_BUFFER_SIZE = 1024;
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
    (void)length;
}

SensorData MakeSensorData(int32_t sensorType, float sensorValue)
{
    SensorData sensorData;
    (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
    sensorData.sensorTypeId = sensorType;
    sensorData.dataLen = sizeof(float);
    (void)memcpy_s(sensorData.data, sizeof(sensorData.data), &sensorValue, sizeof(float));
    return sensorData;
}

void RunChannelStateTests(const sptr<SensorBasicDataChannel> &channel)
{
    if (channel == nullptr) {
        return;
    }
    (void)channel->GetSendDataFd();
    (void)channel->GetReceiveDataFd();
    channel->SetSensorStatus(true);
    (void)channel->GetSensorStatus();
    channel->SetSensorStatus(false);
    (void)channel->GetSensorStatus();
    channel->SetPackageName("testPackage");
    (void)channel->GetPackageName();
    channel->SetPackageName("");
    (void)channel->GetPackageName();
    channel->SetUserId(TEST_USER_ID);
    (void)channel->GetUserId();
    channel->SetAccessTokenId("12345");
    (void)channel->GetAccessTokenId();
    channel->SetAccessTokenId("");
    (void)channel->GetAccessTokenId();
    (void)channel->GetDataCacheBuf();
}

void RunSendDataTests(const sptr<SensorBasicDataChannel> &channel, int32_t sensorType, float sensorValue)
{
    if (channel == nullptr) {
        return;
    }
    SensorData sensorData = MakeSensorData(sensorType, sensorValue);
    channel->SetSensorStatus(true);
    channel->SendData(&sensorData, sizeof(sensorData));

    SensorData events[BATCH_EVENT_COUNT];
    for (size_t index = 0; index < BATCH_EVENT_COUNT; ++index) {
        float currentValue = sensorValue + static_cast<float>(index);
        events[index] = MakeSensorData(sensorType + static_cast<int32_t>(index), currentValue);
    }
    channel->SendData(events, sizeof(events));
    channel->SendData(nullptr, sizeof(SensorData));
    channel->SendData(&sensorData, 0);
}

void RunReceiveDataTests(const sptr<SensorBasicDataChannel> &channel, int32_t sensorType, float sensorValue)
{
    if (channel == nullptr) {
        return;
    }
    SensorData sensorData = MakeSensorData(sensorType, sensorValue);
    channel->SendData(&sensorData, sizeof(sensorData));

    char recvBuf[LARGE_RECEIVE_BUFFER_SIZE] = {0};
    channel->ReceiveData(RecvCallback, recvBuf, sizeof(recvBuf));

    char smallRecvBuf[SMALL_RECEIVE_BUFFER_SIZE] = {0};
    channel->ReceiveData(nullptr, smallRecvBuf, sizeof(smallRecvBuf));
    channel->ReceiveData(RecvCallback, nullptr, SMALL_RECEIVE_BUFFER_SIZE);
}

void RunBinderAndDestroyTests(const sptr<SensorBasicDataChannel> &channel)
{
    if (channel == nullptr) {
        return;
    }
    MessageParcel parcel;
    channel->SendToBinder(parcel);

    channel->CloseSendFd();
    SensorData sensorData;
    (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
    channel->SendData(&sensorData, sizeof(sensorData));

    channel->DestroySensorBasicChannel();
    channel->DestroySensorBasicChannel();
}

void RunCreateFromParcelTests()
{
    sptr<SensorBasicDataChannel> srcChannel = new (std::nothrow) SensorBasicDataChannel();
    if (srcChannel == nullptr) {
        return;
    }
    if (srcChannel->CreateSensorBasicChannel() != 0) {
        return;
    }
    MessageParcel parcel;
    srcChannel->SendToBinder(parcel);

    sptr<SensorBasicDataChannel> dstChannel = new (std::nothrow) SensorBasicDataChannel();
    if (dstChannel == nullptr) {
        srcChannel->DestroySensorBasicChannel();
        return;
    }
    dstChannel->CreateSensorBasicChannel(parcel);
    dstChannel->DestroySensorBasicChannel();
    srcChannel->DestroySensorBasicChannel();
}

void RunCreateBySendFdTests()
{
    sptr<SensorBasicDataChannel> invalidChannel = new (std::nothrow) SensorBasicDataChannel();
    if (invalidChannel == nullptr) {
        return;
    }
    invalidChannel->CreateSensorBasicChannelBySendFd(INVALID_FD);
    invalidChannel->DestroySensorBasicChannel();

    sptr<SensorBasicDataChannel> srcChannel = new (std::nothrow) SensorBasicDataChannel();
    if (srcChannel == nullptr) {
        return;
    }
    if (srcChannel->CreateSensorBasicChannel() != 0) {
        return;
    }
    int32_t fd = srcChannel->GetSendDataFd();
    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel == nullptr) {
        return;
    }
    channel->CreateSensorBasicChannelBySendFd(fd);
    channel->CreateSensorBasicChannelBySendFd(fd + NEXT_SENSOR_OFFSET);
}

void RunDefaultStateTests()
{
    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel == nullptr) {
        return;
    }
    (void)channel->GetSensorStatus();
    (void)channel->GetPackageName();
    (void)channel->GetUserId();
    (void)channel->GetAccessTokenId();
    (void)channel->GetDataCacheBuf();
    (void)channel->GetSendDataFd();
    (void)channel->GetReceiveDataFd();

    SensorData sensorData;
    (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
    channel->SendData(&sensorData, sizeof(sensorData));

    MessageParcel parcel;
    channel->SendToBinder(parcel);
}

bool SensorBasicDataChannelFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;
    float sensorValue = 0.0f;
    startPos += GetObject<float>(sensorValue, data + startPos, size - startPos);
    int32_t sensorType = 0;
    startPos += GetObject<int32_t>(sensorType, data + startPos, size - startPos);

    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel == nullptr) {
        return false;
    }
    if (channel->CreateSensorBasicChannel() != 0) {
        return true;
    }

    RunChannelStateTests(channel);
    RunSendDataTests(channel, sensorType, sensorValue);
    RunReceiveDataTests(channel, sensorType, sensorValue);
    RunBinderAndDestroyTests(channel);
    RunCreateFromParcelTests();
    RunCreateBySendFdTests();
    RunDefaultStateTests();
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
