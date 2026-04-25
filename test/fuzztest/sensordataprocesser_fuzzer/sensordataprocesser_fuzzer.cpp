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

static SensorData MakeSensorData(int32_t sensorType, int32_t deviceId, int32_t sensorId,
    int32_t location, uint32_t mode, float value, int64_t timestamp)
{
    SensorData data;
    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    data.sensorTypeId = sensorType;
    data.deviceId = deviceId;
    data.sensorId = sensorId;
    data.location = location;
    data.mode = mode;
    data.timestamp = timestamp;
    data.dataLen = sizeof(float);
    (void)memcpy_s(data.data, sizeof(data.data), &value, sizeof(float));
    return data;
}

bool SensorDataProcesserFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();
    size_t startPos = 0;

    int32_t sensorType = 0;
    startPos += GetObject<int32_t>(sensorType, data + startPos, size - startPos);
    uint32_t mode = 0;
    startPos += GetObject<uint32_t>(mode, data + startPos, size - startPos);
    float sensorValue = 0.0f;
    startPos += GetObject<float>(sensorValue, data + startPos, size - startPos);
    int64_t timestamp = 0;
    startPos += GetObject<int64_t>(timestamp, data + startPos, size - startPos);
    int64_t samplingPeriodNs = 0;
    startPos += GetObject<int64_t>(samplingPeriodNs, data + startPos, size - startPos);
    int64_t maxReportDelayNs = 0;
    startPos += GetObject<int64_t>(maxReportDelayNs, data + startPos, size - startPos);
    uint64_t periodCount = 0;
    startPos += GetObject<uint64_t>(periodCount, data + startPos, size - startPos);
    uint64_t fifoCount = 0;
    startPos += GetObject<uint64_t>(fifoCount, data + startPos, size - startPos);

    SensorDescription sensorDesc {
        .deviceId = TEST_DEVICE_ID,
        .sensorType = sensorType,
        .sensorId = TEST_SENSOR_ID,
        .location = TEST_LOCATION
    };

    // Build a sensor map with the fuzzed sensor type
    Sensor sensor;
    sensor.SetSensorTypeId(sensorType);
    sensor.SetDeviceId(TEST_DEVICE_ID);
    sensor.SetSensorId(TEST_SENSOR_ID);
    sensor.SetLocation(TEST_LOCATION);
    sensor.SetFlags(mode);
    sensor.SetMinSamplePeriodNs(100000);
    sensor.SetMaxSamplePeriodNs(1000000000);
    sensor.SetFifoMaxEventCount(100);

    std::unordered_map<SensorDescription, Sensor> sensorMap;
    sensorMap.insert(std::make_pair(sensorDesc, sensor));

    // Create the SensorDataProcesser
    sptr<SensorDataProcesser> processer = new (std::nothrow) SensorDataProcesser(sensorMap);
    if (processer == nullptr) {
        return false;
    }

    // Set up ClientInfo with channel and sensor info for the test pid
    ClientInfo &clientInfo = ClientInfo::GetInstance();
    clientInfo.UpdateAppThreadInfo(TEST_PID, TEST_UID, 0);

    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel == nullptr) {
        return false;
    }
    // Create actual socket pair so SendData won't fail on invalid fd
    channel->CreateSensorBasicChannel();
    channel->SetSensorStatus(true);

    clientInfo.UpdateSensorChannel(TEST_PID, channel);

    SensorBasicInfo sensorInfo;
    if (samplingPeriodNs <= 0) {
        samplingPeriodNs = 100000;
    }
    sensorInfo.SetSamplingPeriodNs(samplingPeriodNs);
    sensorInfo.SetMaxReportDelayNs(maxReportDelayNs);
    sensorInfo.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc, TEST_PID, sensorInfo);

    SensorData sensorData = MakeSensorData(sensorType, TEST_DEVICE_ID, TEST_SENSOR_ID,
        TEST_LOCATION, mode, sensorValue, timestamp);

    // ===== 1. SendRawData =====
    {
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        std::vector<SensorData> events;
        events.push_back(sensorData);
        processer->SendRawData(cacheBuf, channel, events);
    }
    // Empty events
    {
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        std::vector<SensorData> events;
        processer->SendRawData(cacheBuf, channel, events);
    }
    // Null channel
    {
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        std::vector<SensorData> events;
        events.push_back(sensorData);
        sptr<SensorBasicDataChannel> nullChannel = nullptr;
        processer->SendRawData(cacheBuf, nullChannel, events);
    }

    // ===== 2. ReportNotContinuousData =====
    {
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        // ON_CHANGE mode
        SensorData onChangeData = sensorData;
        onChangeData.mode = 1;  // SENSOR_ON_CHANGE
        processer->ReportNotContinuousData(cacheBuf, channel, onChangeData);
    }
    {
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        // ONE_SHOT mode
        SensorData oneShotData = sensorData;
        oneShotData.mode = 2;  // SENSOR_ONE_SHOT
        processer->ReportNotContinuousData(cacheBuf, channel, oneShotData);
    }
    {
        // Continuous mode - should return false
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        SensorData contData = sensorData;
        contData.mode = 0;
        processer->ReportNotContinuousData(cacheBuf, channel, contData);
    }
    {
        // Sensor not in map
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        SensorData unknownData = sensorData;
        unknownData.sensorTypeId = sensorType + 999;
        processer->ReportNotContinuousData(cacheBuf, channel, unknownData);
    }

    // ===== 3. SendNoneFifoCacheData =====
    {
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        uint64_t pc = (periodCount == 0) ? 1 : periodCount;
        processer->SendNoneFifoCacheData(cacheBuf, channel, sensorData, pc);
        // Call again - channel should already exist in dataCountMap
        processer->SendNoneFifoCacheData(cacheBuf, channel, sensorData, pc);
    }
    // With periodCount = 0
    {
        std::unordered_map<SensorDescription, SensorData> cacheBuf;
        processer->SendNoneFifoCacheData(cacheBuf, channel, sensorData, 0);
    }
    // With a different channel (to test channelExist=false path)
    {
        sptr<SensorBasicDataChannel> channel2 = new (std::nothrow) SensorBasicDataChannel();
        if (channel2 != nullptr) {
            channel2->CreateSensorBasicChannel();
            channel2->SetSensorStatus(true);
            std::unordered_map<SensorDescription, SensorData> cacheBuf;
            // First call creates entry, second call with different channel hits !channelExist
            processer->SendNoneFifoCacheData(cacheBuf, channel, sensorData, 1);
            processer->SendNoneFifoCacheData(cacheBuf, channel2, sensorData, 1);
        }
    }

    // ===== 4. SendFifoCacheData =====
    // Clear dataCountMap by creating a fresh processer
    {
        sptr<SensorDataProcesser> processer2 = new (std::nothrow) SensorDataProcesser(sensorMap);
        if (processer2 != nullptr) {
            std::unordered_map<SensorDescription, SensorData> cacheBuf;
            uint64_t pc = (periodCount == 0) ? 1 : periodCount;
            uint64_t fc = (fifoCount <= 1) ? 3 : fifoCount;
            // First call - no entry yet
            processer2->SendFifoCacheData(cacheBuf, channel, sensorData, pc, fc);
            // Subsequent calls to accumulate fifo
            for (uint64_t i = 0; i < fc + 2; i++) {
                SensorData d = sensorData;
                d.timestamp = timestamp + static_cast<int64_t>(i);
                processer2->SendFifoCacheData(cacheBuf, channel, d, pc, fc);
            }
        }
    }

    // ===== 5. CacheSensorEvent =====
    {
        // No cache - first send
        processer->CacheSensorEvent(sensorData, channel);
    }
    {
        // With existing cache entry - force a cache entry first
        auto &cacheBuf = const_cast<std::unordered_map<SensorDescription, SensorData> &>(
            channel->GetDataCacheBuf());
        cacheBuf[sensorDesc] = sensorData;
        processer->CacheSensorEvent(sensorData, channel);
        cacheBuf.clear();
    }
    // Null channel
    {
        sptr<SensorBasicDataChannel> nullCh = nullptr;
        processer->CacheSensorEvent(sensorData, nullCh);
    }

    // ===== 6. ReportData =====
    {
        processer->ReportData(channel, sensorData);
    }
    // Null channel
    {
        sptr<SensorBasicDataChannel> nullCh = nullptr;
        processer->ReportData(nullCh, sensorData);
    }

    // ===== 7. SendEvents =====
    {
        processer->SendEvents(channel, sensorData);
    }
    // Null channel
    {
        sptr<SensorBasicDataChannel> nullCh = nullptr;
        processer->SendEvents(nullCh, sensorData);
    }

    // ===== 8. UpdateSensorMap =====
    {
        Sensor sensor2;
        sensor2.SetSensorTypeId(sensorType + 1);
        sensor2.SetDeviceId(TEST_DEVICE_ID);
        sensor2.SetSensorId(TEST_SENSOR_ID + 1);
        sensor2.SetLocation(TEST_LOCATION);
        std::unordered_map<SensorDescription, Sensor> newMap;
        SensorDescription desc2 {TEST_DEVICE_ID, sensorType + 1, TEST_SENSOR_ID + 1, TEST_LOCATION};
        newMap[desc2] = sensor2;
        processer->UpdateSensorMap(newMap);
    }

    // ===== 9. EventFilter - requires CircularEventBuf =====
    {
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

    // Cleanup
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
