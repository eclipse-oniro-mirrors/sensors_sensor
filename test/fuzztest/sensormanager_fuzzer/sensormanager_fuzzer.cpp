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

#include "sensormanager_fuzzer.h"

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
#include "sensor_manager.h"

namespace OHOS {
namespace Sensors {
using namespace Security::AccessToken;
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t PROXIMITY_SENSOR_ID = 50331904;
constexpr uint32_t DEFAULT_PID = 1001;
constexpr uint32_t NEXT_PID_OFFSET = 1;
constexpr int32_t DEFAULT_UID = 2001;
constexpr int32_t NEXT_UID = 2002;
constexpr int32_t ACCELEROMETER_TYPE = 1;
constexpr int32_t ACCELEROMETER_SENSOR_ID = 1;
constexpr int32_t DEFAULT_DEVICE_ID = 0;
constexpr int32_t UNKNOWN_PID = 99999;
constexpr int64_t SHORT_SAMPLING_PERIOD_NS = 1000;
constexpr int64_t DEFAULT_SAMPLING_PERIOD_NS = 10000000;
constexpr int64_t SENSOR_MIN_SAMPLE_PERIOD_NS = 5000000;
constexpr int32_t SENSOR_FIFO_MAX_EVENT_COUNT = 1000;

struct SensorManagerFuzzInput {
    uint32_t pid = 0;
    int32_t sensorType = 0;
    int64_t samplingPeriodNs = 0;
    int64_t maxReportDelayNs = 0;
    uint32_t tokenIdVal = 0;
    int32_t isAccessTokenActive = 0;
};

struct SensorManagerTestConfig {
    uint32_t pid = 0;
    uint32_t tokenIdVal = 0;
    int64_t samplingPeriodNs = 0;
    int64_t maxReportDelayNs = 0;
};

struct SensorManagerTestDescriptors {
    SensorDescription sensorDesc1 {};
    SensorDescription sensorDescFuzz {};
    SensorDescription sensorDescProximity {};
};

struct SensorManagerTestContext {
    SensorManagerTestConfig config;
    SensorManagerTestDescriptors descriptors;
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

void ReadFuzzInput(const uint8_t *data, size_t size, SensorManagerFuzzInput &input)
{
    size_t startPos = 0;
    startPos += GetObject<uint32_t>(input.pid, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.sensorType, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.samplingPeriodNs, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.maxReportDelayNs, data + startPos, size - startPos);
    startPos += GetObject<uint32_t>(input.tokenIdVal, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.isAccessTokenActive, data + startPos, size - startPos);
}

void NormalizeInput(SensorManagerFuzzInput &input)
{
    if (input.pid == 0) {
        input.pid = DEFAULT_PID;
    }
    if (input.samplingPeriodNs <= 0) {
        input.samplingPeriodNs = DEFAULT_SAMPLING_PERIOD_NS;
    }
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
        .processName = "SensorManagerFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

Sensor CreateBaseSensor()
{
    Sensor sensor;
    (void)memset_s(&sensor, sizeof(sensor), 0, sizeof(sensor));
    sensor.SetMinSamplePeriodNs(SENSOR_MIN_SAMPLE_PERIOD_NS);
    sensor.SetFifoMaxEventCount(SENSOR_FIFO_MAX_EVENT_COUNT);
    return sensor;
}

void PrepareSensorMap(SensorManager &sensorMgr, const SensorDescription &sensorDesc1,
    const SensorDescription &sensorDescProximity, const Sensor &sensor1, const Sensor &sensorProximity)
{
    std::lock_guard<std::mutex> lock(sensorMgr.sensorMapMutex_);
    sensorMgr.sensorMap_.clear();
    sensorMgr.sensorMap_[sensorDesc1] = sensor1;
    sensorMgr.sensorMap_[sensorDescProximity] = sensorProximity;
}

void PrepareClientInfoState(ClientInfo &clientInfo, uint32_t pid)
{
    clientInfo.UpdateAppThreadInfo(pid, DEFAULT_UID, 0);
    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel != nullptr) {
        channel->CreateSensorBasicChannel();
        channel->SetSensorStatus(true);
        clientInfo.UpdateSensorChannel(pid, channel);
    }
}

void RunGetSensorInfoTests(SensorManager &sensorMgr, const SensorManagerTestContext &context)
{
    (void)sensorMgr.GetSensorInfo(context.descriptors.sensorDesc1,
        context.config.samplingPeriodNs, context.config.maxReportDelayNs);
    (void)sensorMgr.GetSensorInfo(context.descriptors.sensorDescFuzz,
        context.config.samplingPeriodNs, context.config.maxReportDelayNs);
    (void)sensorMgr.GetSensorInfo(context.descriptors.sensorDesc1, 0, context.config.maxReportDelayNs);
    (void)sensorMgr.GetSensorInfo(context.descriptors.sensorDesc1, INT64_MAX, context.config.maxReportDelayNs);
    (void)sensorMgr.GetSensorInfo(context.descriptors.sensorDesc1,
        SHORT_SAMPLING_PERIOD_NS, context.config.maxReportDelayNs);
    (void)sensorMgr.GetSensorInfo(context.descriptors.sensorDesc1, context.config.samplingPeriodNs, INT64_MAX);
}

void RunSaveSubscriberTests(SensorManager &sensorMgr, const SensorManagerTestContext &context)
{
    (void)sensorMgr.SaveSubscriber(context.descriptors.sensorDesc1, context.config.pid,
        context.config.samplingPeriodNs, context.config.maxReportDelayNs);
    (void)sensorMgr.SaveSubscriber(context.descriptors.sensorDescFuzz, context.config.pid,
        context.config.samplingPeriodNs, context.config.maxReportDelayNs);
    (void)sensorMgr.SaveSubscriber(context.descriptors.sensorDesc1, context.config.pid, 0, 0);
    (void)sensorMgr.SaveSubscriber(context.descriptors.sensorDesc1, 0,
        context.config.samplingPeriodNs, context.config.maxReportDelayNs);
}

void AddSecondClientSubscription(ClientInfo &clientInfo, const SensorManagerTestContext &context)
{
    uint32_t pid2 = context.config.pid + NEXT_PID_OFFSET;
    clientInfo.UpdateAppThreadInfo(pid2, NEXT_UID, 0);
    sptr<SensorBasicDataChannel> channel2 = new (std::nothrow) SensorBasicDataChannel();
    if (channel2 != nullptr) {
        channel2->CreateSensorBasicChannel();
        channel2->SetSensorStatus(true);
        clientInfo.UpdateSensorChannel(pid2, channel2);
    }

    SensorBasicInfo sensorInfo;
    sensorInfo.SetSamplingPeriodNs(context.config.samplingPeriodNs);
    sensorInfo.SetMaxReportDelayNs(context.config.maxReportDelayNs);
    sensorInfo.SetSensorState(true);
    clientInfo.UpdateSensorInfo(context.descriptors.sensorDesc1, pid2, sensorInfo);
}

void RunOtherClientUsingSensorTests(SensorManager &sensorMgr, ClientInfo &clientInfo,
    const SensorManagerTestContext &context)
{
    (void)sensorMgr.IsOtherClientUsingSensor(context.descriptors.sensorDesc1, context.config.pid);
    AddSecondClientSubscription(clientInfo, context);
    (void)sensorMgr.IsOtherClientUsingSensor(context.descriptors.sensorDesc1, context.config.pid);
    uint32_t pid2 = context.config.pid + NEXT_PID_OFFSET;
    clientInfo.DestroySensorChannel(pid2);
    (void)sensorMgr.IsOtherClientUsingSensor(context.descriptors.sensorDesc1, UNKNOWN_PID);
}

void RunAfterDisableSensorTests(SensorManager &sensorMgr, ClientInfo &clientInfo,
    const SensorDescription &sensorDesc1, const SensorDescription &sensorDescProximity)
{
    (void)sensorMgr.AfterDisableSensor(sensorDesc1);

    SensorData sensorData;
    (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
    sensorData.sensorTypeId = PROXIMITY_SENSOR_ID;
    sensorData.dataLen = sizeof(float);
    sensorData.data[0] = 0.0f;
    clientInfo.StoreEvent(sensorData);
    (void)sensorMgr.AfterDisableSensor(sensorDescProximity);

    clientInfo.ClearSensorInfo(sensorDescProximity);
    (void)sensorMgr.AfterDisableSensor(sensorDescProximity);
}

void InitSensorMapForTest(SensorManager &sensorMgr, const std::unordered_map<SensorDescription, Sensor> &sensorMap)
{
#ifdef HDF_DRIVERS_INTERFACE_SENSOR
    sensorMgr.InitSensorMap(sensorMap, nullptr, nullptr);
#else
    sensorMgr.InitSensorMap(sensorMap);
#endif // HDF_DRIVERS_INTERFACE_SENSOR
}

void RunGetPackageNameTests(SensorManager &sensorMgr, uint32_t tokenIdVal)
{
    std::string packageName;
    SensorManager::SetAccessTokenServiceActive(true);
    sensorMgr.GetPackageName(tokenIdVal, packageName);
    SensorManager::SetAccessTokenServiceActive(false);
    sensorMgr.GetPackageName(tokenIdVal, packageName);
    SensorManager::SetAccessTokenServiceActive(true);
    sensorMgr.GetPackageName(0, packageName);
    sensorMgr.GetPackageName(static_cast<AccessTokenID>(GetSelfTokenID()), packageName);
    SensorManager::SetAccessTokenServiceActive(false);
    sensorMgr.GetPackageName(static_cast<AccessTokenID>(GetSelfTokenID()), packageName);
}

void RunInitSensorMapTests(SensorManager &sensorMgr, const Sensor &sensor1,
    const SensorManagerTestContext &context)
{
    std::unordered_map<SensorDescription, Sensor> testMap;
    testMap[context.descriptors.sensorDesc1] = sensor1;
    InitSensorMapForTest(sensorMgr, testMap);
    std::unordered_map<SensorDescription, Sensor> emptyMap;
    InitSensorMapForTest(sensorMgr, emptyMap);
    InitSensorMapForTest(sensorMgr, testMap);
    (void)sensorMgr.GetSensorInfo(context.descriptors.sensorDesc1,
        context.config.samplingPeriodNs, context.config.maxReportDelayNs);
}

void CleanupClientInfoState(ClientInfo &clientInfo, const SensorManagerTestContext &context)
{
    clientInfo.ClearSensorInfo(context.descriptors.sensorDesc1);
    clientInfo.ClearSensorInfo(context.descriptors.sensorDescProximity);
    clientInfo.DestroySensorChannel(context.config.pid);
}
} // namespace

bool SensorManagerFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();

    SensorManagerFuzzInput input;
    ReadFuzzInput(data, size, input);
    NormalizeInput(input);

    SensorManager &sensorMgr = SensorManager::GetInstance();
    ClientInfo &clientInfo = ClientInfo::GetInstance();
    SensorManagerTestContext context;
    context.config.pid = input.pid;
    context.config.tokenIdVal = input.tokenIdVal;
    context.config.samplingPeriodNs = input.samplingPeriodNs;
    context.config.maxReportDelayNs = input.maxReportDelayNs;
    context.descriptors.sensorDesc1.sensorType = ACCELEROMETER_TYPE;
    context.descriptors.sensorDesc1.sensorId = ACCELEROMETER_SENSOR_ID;
    context.descriptors.sensorDesc1.deviceId = DEFAULT_DEVICE_ID;
    context.descriptors.sensorDescProximity.sensorType = PROXIMITY_SENSOR_ID;
    context.descriptors.sensorDescProximity.sensorId = PROXIMITY_SENSOR_ID;
    context.descriptors.sensorDescProximity.deviceId = DEFAULT_DEVICE_ID;
    context.descriptors.sensorDescFuzz.sensorType = input.sensorType;
    context.descriptors.sensorDescFuzz.sensorId = input.sensorType;
    context.descriptors.sensorDescFuzz.deviceId = DEFAULT_DEVICE_ID;

    Sensor sensor1 = CreateBaseSensor();
    Sensor sensorProximity = CreateBaseSensor();
    PrepareSensorMap(sensorMgr, context.descriptors.sensorDesc1, context.descriptors.sensorDescProximity,
        sensor1, sensorProximity);
    PrepareClientInfoState(clientInfo, context.config.pid);
    RunGetSensorInfoTests(sensorMgr, context);
    RunSaveSubscriberTests(sensorMgr, context);
    RunOtherClientUsingSensorTests(sensorMgr, clientInfo, context);
    RunAfterDisableSensorTests(sensorMgr, clientInfo,
        context.descriptors.sensorDesc1, context.descriptors.sensorDescProximity);
    RunGetPackageNameTests(sensorMgr, context.config.tokenIdVal);
    RunInitSensorMapTests(sensorMgr, sensor1, context);
    CleanupClientInfoState(clientInfo, context);
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
    OHOS::Sensors::SensorManagerFuzzTest(data, size);
    return 0;
}
