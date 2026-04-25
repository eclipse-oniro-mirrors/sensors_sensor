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

#include "sensordataprocesser_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "client_info.h"
#include "sensor.h"
#include "sensor_basic_data_channel.h"
#include "sensor_basic_info.h"
#include "sensor_data_processer.h"
#include "report_data_callback.h"

namespace OHOS {
namespace Sensors {
using namespace Security::AccessToken;
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t TEST_PID = 1000;
constexpr int32_t TEST_UID = 2000;
constexpr int32_t TEST_DEVICE_ID = 0;
constexpr int32_t TEST_SENSOR_ID = 0;
constexpr int32_t TEST_LOCATION = 1;
constexpr int32_t SENSOR_ON_CHANGE_MODE = 1;
constexpr int32_t SENSOR_ONE_SHOT_MODE = 2;
constexpr int32_t UNKNOWN_SENSOR_OFFSET = 999;
constexpr int64_t MIN_SAMPLE_PERIOD_NS = 100000;
constexpr int64_t MAX_SAMPLE_PERIOD_NS = 1000000000;
constexpr int32_t DEFAULT_FIFO_MAX_EVENT_COUNT = 100;
constexpr uint64_t DEFAULT_PERIOD_COUNT = 1;
constexpr uint64_t DEFAULT_FIFO_COUNT = 3;
constexpr uint64_t FIFO_EXTRA_EVENTS = 2;

struct SensorDataProcesserFuzzInput {
    int32_t sensorType = 0;
    uint32_t mode = 0;
    float sensorValue = 0.0f;
    int64_t timestamp = 0;
    int64_t samplingPeriodNs = 0;
    int64_t maxReportDelayNs = 0;
    uint64_t periodCount = 0;
    uint64_t fifoCount = 0;
};

struct SensorDataSpec {
    int32_t sensorType = 0;
    int32_t deviceId = 0;
    int32_t sensorId = 0;
    int32_t location = 0;
    uint32_t mode = 0;
    float value = 0.0f;
    int64_t timestamp = 0;
};

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

void ReadFuzzInput(const uint8_t *data, size_t size, SensorDataProcesserFuzzInput &input)
{
    size_t startPos = 0;
    startPos += GetObject<int32_t>(input.sensorType, data + startPos, size - startPos);
    startPos += GetObject<uint32_t>(input.mode, data + startPos, size - startPos);
    startPos += GetObject<float>(input.sensorValue, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.timestamp, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.samplingPeriodNs, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.maxReportDelayNs, data + startPos, size - startPos);
    startPos += GetObject<uint64_t>(input.periodCount, data + startPos, size - startPos);
    startPos += GetObject<uint64_t>(input.fifoCount, data + startPos, size - startPos);
}

void SetUpTestCase()
{
    const char **perms = new (std::nothrow) const char *[2];
    if (perms == nullptr) {
        return;
    }
    perms[0] = "ohos.permission.ACCELEROMETER";
    perms[1] = "ohos.permission.MANAGE_SENSOR";
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "SensorDataProcesserFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

SensorData MakeSensorData(const SensorDataSpec &spec)
{
    SensorData data;
    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    data.sensorTypeId = spec.sensorType;
    data.deviceId = spec.deviceId;
    data.sensorId = spec.sensorId;
    data.location = spec.location;
    data.mode = spec.mode;
    data.timestamp = spec.timestamp;
    data.dataLen = sizeof(float);
    (void)memcpy_s(data.data, sizeof(data.data), &spec.value, sizeof(float));
    return data;
}

SensorDescription BuildSensorDesc(int32_t sensorType)
{
    SensorDescription sensorDesc {
        .deviceId = TEST_DEVICE_ID,
        .sensorType = sensorType,
        .sensorId = TEST_SENSOR_ID,
        .location = TEST_LOCATION
    };
    return sensorDesc;
}

std::unordered_map<SensorDescription, Sensor> BuildSensorMap(const SensorDescription &sensorDesc,
    int32_t sensorType, uint32_t mode)
{
    Sensor sensor;
    sensor.SetSensorTypeId(sensorType);
    sensor.SetDeviceId(TEST_DEVICE_ID);
    sensor.SetSensorId(TEST_SENSOR_ID);
    sensor.SetLocation(TEST_LOCATION);
    sensor.SetFlags(mode);
    sensor.SetMinSamplePeriodNs(MIN_SAMPLE_PERIOD_NS);
    sensor.SetMaxSamplePeriodNs(MAX_SAMPLE_PERIOD_NS);
    sensor.SetFifoMaxEventCount(DEFAULT_FIFO_MAX_EVENT_COUNT);

    std::unordered_map<SensorDescription, Sensor> sensorMap;
    sensorMap.emplace(sensorDesc, sensor);
    return sensorMap;
}

sptr<SensorBasicDataChannel> PrepareClientInfo(ClientInfo &clientInfo, const SensorDescription &sensorDesc,
    int64_t samplingPeriodNs, int64_t maxReportDelayNs)
{
    clientInfo.UpdateAppThreadInfo(TEST_PID, TEST_UID, 0);

    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel == nullptr) {
        return nullptr;
    }
    channel->CreateSensorBasicChannel();
    channel->SetSensorStatus(true);
    clientInfo.UpdateSensorChannel(TEST_PID, channel);

    SensorBasicInfo sensorInfo;
    sensorInfo.SetSamplingPeriodNs(samplingPeriodNs <= 0 ? MIN_SAMPLE_PERIOD_NS : samplingPeriodNs);
    sensorInfo.SetMaxReportDelayNs(maxReportDelayNs);
    sensorInfo.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc, TEST_PID, sensorInfo);
    return channel;
}

void RunSendRawDataTests(const sptr<SensorDataProcesser> &processer,
    const sptr<SensorBasicDataChannel> &channel, const SensorData &sensorData)
{
    std::unordered_map<SensorDescription, SensorData> cacheBuf;
    std::vector<SensorData> events = { sensorData };
    processer->SendRawData(cacheBuf, channel, events);

    events.clear();
    processer->SendRawData(cacheBuf, channel, events);

    sptr<SensorBasicDataChannel> nullChannel = nullptr;
    events.push_back(sensorData);
    processer->SendRawData(cacheBuf, nullChannel, events);
}

void RunReportNotContinuousDataTests(const sptr<SensorDataProcesser> &processer,
    sptr<SensorBasicDataChannel> &channel, const SensorData &sensorData, int32_t sensorType)
{
    std::unordered_map<SensorDescription, SensorData> cacheBuf;
    SensorData onChangeData = sensorData;
    onChangeData.mode = SENSOR_ON_CHANGE_MODE;
    processer->ReportNotContinuousData(cacheBuf, channel, onChangeData);

    SensorData oneShotData = sensorData;
    oneShotData.mode = SENSOR_ONE_SHOT_MODE;
    processer->ReportNotContinuousData(cacheBuf, channel, oneShotData);

    SensorData continuousData = sensorData;
    continuousData.mode = 0;
    processer->ReportNotContinuousData(cacheBuf, channel, continuousData);

    SensorData unknownData = sensorData;
    unknownData.sensorTypeId = sensorType + UNKNOWN_SENSOR_OFFSET;
    processer->ReportNotContinuousData(cacheBuf, channel, unknownData);
}

void RunNoneFifoCacheDataTests(const sptr<SensorDataProcesser> &processer,
    sptr<SensorBasicDataChannel> &channel, SensorData &sensorData, uint64_t periodCount)
{
    std::unordered_map<SensorDescription, SensorData> cacheBuf;
    uint64_t currentPeriodCount = (periodCount == 0) ? DEFAULT_PERIOD_COUNT : periodCount;
    processer->SendNoneFifoCacheData(cacheBuf, channel, sensorData, currentPeriodCount);
    processer->SendNoneFifoCacheData(cacheBuf, channel, sensorData, currentPeriodCount);
    processer->SendNoneFifoCacheData(cacheBuf, channel, sensorData, 0);

    sptr<SensorBasicDataChannel> channel2 = new (std::nothrow) SensorBasicDataChannel();
    if (channel2 != nullptr) {
        channel2->CreateSensorBasicChannel();
        channel2->SetSensorStatus(true);
        processer->SendNoneFifoCacheData(cacheBuf, channel, sensorData, DEFAULT_PERIOD_COUNT);
        processer->SendNoneFifoCacheData(cacheBuf, channel2, sensorData, DEFAULT_PERIOD_COUNT);
    }
}

void RunFifoCacheDataTests(const std::unordered_map<SensorDescription, Sensor> &sensorMap,
    sptr<SensorBasicDataChannel> &channel, SensorData &sensorData,
    uint64_t periodCount, uint64_t fifoCount, int64_t timestamp)
{
    sptr<SensorDataProcesser> processer = new (std::nothrow) SensorDataProcesser(sensorMap);
    if (processer == nullptr) {
        return;
    }

    std::unordered_map<SensorDescription, SensorData> cacheBuf;
    uint64_t currentPeriodCount = (periodCount == 0) ? DEFAULT_PERIOD_COUNT : periodCount;
    uint64_t currentFifoCount = (fifoCount <= DEFAULT_PERIOD_COUNT) ? DEFAULT_FIFO_COUNT : fifoCount;
    processer->SendFifoCacheData(cacheBuf, channel, sensorData, currentPeriodCount, currentFifoCount);
    for (uint64_t index = 0; index < currentFifoCount + FIFO_EXTRA_EVENTS; ++index) {
        SensorData currentData = sensorData;
        currentData.timestamp = timestamp + static_cast<int64_t>(index);
        processer->SendFifoCacheData(cacheBuf, channel, currentData, currentPeriodCount, currentFifoCount);
    }
}

void RunCacheAndSendEventTests(const sptr<SensorDataProcesser> &processer,
    sptr<SensorBasicDataChannel> &channel, SensorData &sensorData,
    const SensorDescription &sensorDesc)
{
    processer->CacheSensorEvent(sensorData, channel);

    auto &cacheBuf = const_cast<std::unordered_map<SensorDescription, SensorData> &>(channel->GetDataCacheBuf());
    cacheBuf[sensorDesc] = sensorData;
    processer->CacheSensorEvent(sensorData, channel);
    cacheBuf.clear();

    sptr<SensorBasicDataChannel> nullChannel = nullptr;
    processer->CacheSensorEvent(sensorData, nullChannel);
    processer->ReportData(channel, sensorData);
    processer->ReportData(nullChannel, sensorData);
    processer->SendEvents(channel, sensorData);
    processer->SendEvents(nullChannel, sensorData);
}

void RunUpdateSensorMapAndFilterTests(const sptr<SensorDataProcesser> &processer,
    int32_t sensorType, const SensorData &sensorData)
{
    Sensor sensor;
    sensor.SetSensorTypeId(sensorType + 1);
    sensor.SetDeviceId(TEST_DEVICE_ID);
    sensor.SetSensorId(TEST_SENSOR_ID + 1);
    sensor.SetLocation(TEST_LOCATION);

    SensorDescription sensorDesc { TEST_DEVICE_ID, sensorType + 1, TEST_SENSOR_ID + 1, TEST_LOCATION };
    std::unordered_map<SensorDescription, Sensor> sensorMap;
    sensorMap[sensorDesc] = sensor;
    processer->UpdateSensorMap(sensorMap);

    sptr<ReportDataCallback> callback = new (std::nothrow) ReportDataCallback();
    if (callback != nullptr) {
        auto &eventsBuf = callback->GetEventData();
        if (eventsBuf.circularBuf != nullptr) {
            eventsBuf.circularBuf[0] = sensorData;
            eventsBuf.readPos = 0;
            eventsBuf.writePosition = 1;
            eventsBuf.eventNum = 1;
            processer->EventFilter(eventsBuf);
        }
    }
}
} // namespace

bool SensorDataProcesserFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();

    SensorDataProcesserFuzzInput input;
    ReadFuzzInput(data, size, input);

    SensorDescription sensorDesc = BuildSensorDesc(input.sensorType);
    std::unordered_map<SensorDescription, Sensor> sensorMap = BuildSensorMap(sensorDesc, input.sensorType, input.mode);
    sptr<SensorDataProcesser> processer = new (std::nothrow) SensorDataProcesser(sensorMap);
    if (processer == nullptr) {
        return false;
    }

    ClientInfo &clientInfo = ClientInfo::GetInstance();
    sptr<SensorBasicDataChannel> channel = PrepareClientInfo(clientInfo, sensorDesc,
        input.samplingPeriodNs, input.maxReportDelayNs);
    if (channel == nullptr) {
        return false;
    }

    SensorDataSpec dataSpec { input.sensorType, TEST_DEVICE_ID, TEST_SENSOR_ID, TEST_LOCATION,
        input.mode, input.sensorValue, input.timestamp };
    SensorData sensorData = MakeSensorData(dataSpec);
    RunSendRawDataTests(processer, channel, sensorData);
    RunReportNotContinuousDataTests(processer, channel, sensorData, input.sensorType);
    RunNoneFifoCacheDataTests(processer, channel, sensorData, input.periodCount);
    RunFifoCacheDataTests(sensorMap, channel, sensorData, input.periodCount, input.fifoCount, input.timestamp);
    RunCacheAndSendEventTests(processer, channel, sensorData, sensorDesc);
    RunUpdateSensorMapAndFilterTests(processer, input.sensorType, sensorData);
    clientInfo.DestroySensorChannel(TEST_PID);
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
    OHOS::Sensors::SensorDataProcesserFuzzTest(data, size);
    return 0;
}
