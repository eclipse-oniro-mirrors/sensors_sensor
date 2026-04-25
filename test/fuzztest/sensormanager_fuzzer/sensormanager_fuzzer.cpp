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
        .processName = "SensorManagerFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

bool SensorManagerFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();
    size_t startPos = 0;

    uint32_t pid = 0;
    startPos += GetObject<uint32_t>(pid, data + startPos, size - startPos);
    int32_t sensorType = 0;
    startPos += GetObject<int32_t>(sensorType, data + startPos, size - startPos);
    int64_t samplingPeriodNs = 0;
    startPos += GetObject<int64_t>(samplingPeriodNs, data + startPos, size - startPos);
    int64_t maxReportDelayNs = 0;
    startPos += GetObject<int64_t>(maxReportDelayNs, data + startPos, size - startPos);
    uint32_t tokenIdVal = 0;
    startPos += GetObject<uint32_t>(tokenIdVal, data + startPos, size - startPos);
    int32_t isAccessTokenActive = 0;
    startPos += GetObject<int32_t>(isAccessTokenActive, data + startPos, size - startPos);

    // Ensure valid pid
    if (pid == 0) {
        pid = 1001;
    }
    if (samplingPeriodNs <= 0) {
        samplingPeriodNs = 10000000;  // 10ms
    }

    SensorManager &sensorMgr = SensorManager::GetInstance();
    ClientInfo &clientInfo = ClientInfo::GetInstance();

    // ===== Setup: populate sensorMap_ with test sensor descriptions =====
    SensorDescription sensorDesc1;
    (void)memset_s(&sensorDesc1, sizeof(sensorDesc1), 0, sizeof(sensorDesc1));
    sensorDesc1.sensorType = 1;  // TYPE_ACCELEROMETER
    sensorDesc1.sensorId = 1;
    sensorDesc1.deviceId = 0;

    SensorDescription sensorDescProximity;
    (void)memset_s(&sensorDescProximity, sizeof(sensorDescProximity), 0, sizeof(sensorDescProximity));
    sensorDescProximity.sensorType = PROXIMITY_SENSOR_ID;
    sensorDescProximity.sensorId = 50331904;
    sensorDescProximity.deviceId = 0;

    SensorDescription sensorDescInvalid;
    (void)memset_s(&sensorDescInvalid, sizeof(sensorDescInvalid), 0, sizeof(sensorDescInvalid));
    sensorDescInvalid.sensorType = -1;  // INVALID_SENSOR_ID
    sensorDescInvalid.sensorId = -1;

    SensorDescription sensorDescFuzz;
    (void)memset_s(&sensorDescFuzz, sizeof(sensorDescFuzz), 0, sizeof(sensorDescFuzz));
    sensorDescFuzz.sensorType = sensorType;
    sensorDescFuzz.sensorId = sensorType;
    sensorDescFuzz.deviceId = 0;

    // Create Sensor objects with valid min/max parameters for GetSensorInfo path
    Sensor sensor1;
    (void)memset_s(&sensor1, sizeof(sensor1), 0, sizeof(sensor1));
    sensor1.SetMinSamplePeriodNs(5000000);   // 5ms
    sensor1.SetFifoMaxEventCount(1000);

    Sensor sensorProximity;
    (void)memset_s(&sensorProximity, sizeof(sensorProximity), 0, sizeof(sensorProximity));
    sensorProximity.SetMinSamplePeriodNs(5000000);
    sensorProximity.SetFifoMaxEventCount(1000);

    // Insert into sensorMap_ (accessing private member via -Dprivate=public)
    {
        std::lock_guard<std::mutex> lock(sensorMgr.sensorMapMutex_);
        sensorMgr.sensorMap_.clear();
        sensorMgr.sensorMap_[sensorDesc1] = sensor1;
        sensorMgr.sensorMap_[sensorDescProximity] = sensorProximity;
    }

    // Setup client info for pid
    clientInfo.UpdateAppThreadInfo(pid, 2001, 0);
    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel != nullptr) {
        channel->CreateSensorBasicChannel();
        channel->SetSensorStatus(true);
        clientInfo.UpdateSensorChannel(pid, channel);
    }

    // ===== 1. GetSensorInfo =====
    {
        // Normal path: sensor found in map, valid params
        SensorBasicInfo info = sensorMgr.GetSensorInfo(sensorDesc1, samplingPeriodNs, maxReportDelayNs);
    }
    {
        // Sensor not found in map (sensorDescFuzz may not be in map)
        SensorBasicInfo info = sensorMgr.GetSensorInfo(sensorDescFuzz, samplingPeriodNs, maxReportDelayNs);
    }
    {
        // samplingPeriodNs = 0 -> overflow check path
        SensorBasicInfo info = sensorMgr.GetSensorInfo(sensorDesc1, 0, maxReportDelayNs);
    }
    {
        // Very large samplingPeriodNs -> overflow path (INT64_MAX / samplingPeriodNs < maxEventCount)
        SensorBasicInfo info = sensorMgr.GetSensorInfo(sensorDesc1, INT64_MAX, maxReportDelayNs);
    }
    {
        // samplingPeriodNs < minSamplePeriodNs -> clamp to min
        SensorBasicInfo info = sensorMgr.GetSensorInfo(sensorDesc1, 1000, maxReportDelayNs);
    }
    {
        // maxReportDelayNs > supportDelay -> clamp to supportDelay
        SensorBasicInfo info = sensorMgr.GetSensorInfo(sensorDesc1, samplingPeriodNs, INT64_MAX);
    }

    // ===== 2. SaveSubscriber =====
    {
        // Normal save
        (void)sensorMgr.SaveSubscriber(sensorDesc1, pid, samplingPeriodNs, maxReportDelayNs);
    }
    {
        // Save with sensor not in map (GetSensorInfo returns default info, UpdateSensorInfo may fail)
        (void)sensorMgr.SaveSubscriber(sensorDescFuzz, pid, samplingPeriodNs, maxReportDelayNs);
    }
    {
        // Save with zero sampling period
        (void)sensorMgr.SaveSubscriber(sensorDesc1, pid, 0, 0);
    }
    {
        // Save with invalid pid (0)
        (void)sensorMgr.SaveSubscriber(sensorDesc1, 0, samplingPeriodNs, maxReportDelayNs);
    }

    // ===== 3. IsOtherClientUsingSensor =====
    {
        // Only current pid using sensor -> returns false
        (void)sensorMgr.IsOtherClientUsingSensor(sensorDesc1, pid);
    }
    {
        // Setup another pid using the same sensor, then check
        uint32_t pid2 = pid + 1;
        clientInfo.UpdateAppThreadInfo(pid2, 2002, 0);
        sptr<SensorBasicDataChannel> channel2 = new (std::nothrow) SensorBasicDataChannel();
        if (channel2 != nullptr) {
            channel2->CreateSensorBasicChannel();
            channel2->SetSensorStatus(true);
            clientInfo.UpdateSensorChannel(pid2, channel2);
        }
        SensorBasicInfo sensorInfo;
        sensorInfo.SetSamplingPeriodNs(samplingPeriodNs);
        sensorInfo.SetMaxReportDelayNs(maxReportDelayNs);
        sensorInfo.SetSensorState(true);
        clientInfo.UpdateSensorInfo(sensorDesc1, pid2, sensorInfo);

        // Now other client is using sensor -> returns true
        (void)sensorMgr.IsOtherClientUsingSensor(sensorDesc1, pid);

        // Cleanup pid2
        clientInfo.DestroySensorChannel(pid2);
    }
    {
        // Non-existent pid
        (void)sensorMgr.IsOtherClientUsingSensor(sensorDesc1, 99999);
    }

    // ===== 4. AfterDisableSensor =====
    {
        // Normal sensor type
        (void)sensorMgr.AfterDisableSensor(sensorDesc1);
    }
    {
        // Proximity sensor type - triggers special path
        // First store a proximity event
        SensorData sensorData;
        (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
        sensorData.sensorTypeId = PROXIMITY_SENSOR_ID;
        sensorData.dataLen = sizeof(float);
        sensorData.data[0] = 0.0f;  // near state
        clientInfo.StoreEvent(sensorData);

        (void)sensorMgr.AfterDisableSensor(sensorDescProximity);
        // After disable, proximity should be set to PROXIMITY_FAR (5.0)
    }
    {
        // Proximity sensor with no stored event (GetStoreEvent fails)
        clientInfo.ClearSensorInfo(sensorDescProximity);
        (void)sensorMgr.AfterDisableSensor(sensorDescProximity);
    }

    // ===== 5. GetPackageName =====
    {
        // Test with fuzzed tokenId, isAccessTokenServiceActive = true
        std::string packageName;
        sensorMgr.GetPackageName(tokenIdVal, packageName, true);
    }
    {
        // Test with isAccessTokenServiceActive = false
        std::string packageName;
        sensorMgr.GetPackageName(tokenIdVal, packageName, false);
    }
    {
        // Test with tokenId = 0 (invalid)
        std::string packageName;
        sensorMgr.GetPackageName(0, packageName, true);
    }
    {
        // Test with a native token (our own test process token)
        std::string packageName;
        uint64_t selfTokenId = GetSelfTokenID();
        sensorMgr.GetPackageName(static_cast<AccessTokenID>(selfTokenId), packageName, true);
    }
    {
        // Test with isAccessTokenServiceActive = false for native token
        std::string packageName;
        uint64_t selfTokenId = GetSelfTokenID();
        sensorMgr.GetPackageName(static_cast<AccessTokenID>(selfTokenId), packageName, false);
    }

    // ===== 6. InitSensorMap (HDF path requires 3 args) =====
    {
        std::unordered_map<SensorDescription, Sensor> testMap;
        testMap[sensorDesc1] = sensor1;
        sensorMgr.InitSensorMap(testMap, nullptr, nullptr);
    }
    {
        // Empty map
        std::unordered_map<SensorDescription, Sensor> emptyMap;
        sensorMgr.InitSensorMap(emptyMap, nullptr, nullptr);
    }

    // ===== 7. GetSensorInfo with sensor in populated map via InitSensorMap =====
    {
        // Re-init map and test GetSensorInfo finds the sensor
        std::unordered_map<SensorDescription, Sensor> testMap;
        testMap[sensorDesc1] = sensor1;
        sensorMgr.InitSensorMap(testMap, nullptr, nullptr);

        SensorBasicInfo info = sensorMgr.GetSensorInfo(sensorDesc1, samplingPeriodNs, maxReportDelayNs);
    }

    // Cleanup
    clientInfo.ClearSensorInfo(sensorDesc1);
    clientInfo.ClearSensorInfo(sensorDescProximity);
    clientInfo.DestroySensorChannel(pid);

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