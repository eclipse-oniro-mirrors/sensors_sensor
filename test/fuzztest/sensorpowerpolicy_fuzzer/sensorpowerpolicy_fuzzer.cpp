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

#include "sensorpowerpolicy_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "active_info.h"
#include "client_info.h"
#include "sensor.h"
#include "sensor_basic_data_channel.h"
#include "sensor_basic_info.h"
#include "sensor_power_policy.h"

namespace OHOS {
namespace Sensors {
using namespace Security::AccessToken;
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
        .processName = "SensorPowerPolicyFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

bool SensorPowerPolicyFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();
    size_t startPos = 0;

    int32_t pid1 = 0;
    startPos += GetObject<int32_t>(pid1, data + startPos, size - startPos);
    int32_t pid2 = 0;
    startPos += GetObject<int32_t>(pid2, data + startPos, size - startPos);
    int32_t sensorType = 0;
    startPos += GetObject<int32_t>(sensorType, data + startPos, size - startPos);
    int64_t samplingPeriodNs = 0;
    startPos += GetObject<int64_t>(samplingPeriodNs, data + startPos, size - startPos);
    int64_t maxReportDelayNs = 0;
    startPos += GetObject<int64_t>(maxReportDelayNs, data + startPos, size - startPos);
    int32_t sensorId2 = 0;
    startPos += GetObject<int32_t>(sensorId2, data + startPos, size - startPos);

    // Ensure valid pids for testing
    if (pid1 <= 0) {
        pid1 = 1001;
    }
    if (pid2 <= 0) {
        pid2 = 1002;
    }
    if (samplingPeriodNs <= 0) {
        samplingPeriodNs = 100000;
    }

    SensorPowerPolicy &powerPolicy = SensorPowerPolicy::GetInstance();
    ClientInfo &clientInfo = ClientInfo::GetInstance();

    SensorDescription sensorDesc1 {0, sensorType, 0, 1};
    // PEDOMETER type to test CheckFreezingSensor path
    SensorDescription sensorDescPedometer {0, 22, 0, 1};  // SENSOR_TYPE_ID_PEDOMETER_DETECTION
    SensorDescription sensorDesc2 {0, sensorType + 1, sensorId2, 1};

    // Setup: register pid1 with sensor subscriptions
    clientInfo.UpdateAppThreadInfo(pid1, 2001, 0);
    sptr<SensorBasicDataChannel> channel1 = new (std::nothrow) SensorBasicDataChannel();
    if (channel1 != nullptr) {
        channel1->CreateSensorBasicChannel();
        channel1->SetSensorStatus(true);
        clientInfo.UpdateSensorChannel(pid1, channel1);
    }

    SensorBasicInfo sensorInfo;
    sensorInfo.SetSamplingPeriodNs(samplingPeriodNs);
    sensorInfo.SetMaxReportDelayNs(maxReportDelayNs);
    sensorInfo.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc1, pid1, sensorInfo);
    clientInfo.UpdateSensorInfo(sensorDescPedometer, pid1, sensorInfo);

    // Setup: register pid2 with same sensor (to test IsOtherClientUsingSensor path)
    clientInfo.UpdateAppThreadInfo(pid2, 2002, 0);
    sptr<SensorBasicDataChannel> channel2 = new (std::nothrow) SensorBasicDataChannel();
    if (channel2 != nullptr) {
        channel2->CreateSensorBasicChannel();
        channel2->SetSensorStatus(true);
        clientInfo.UpdateSensorChannel(pid2, channel2);
    }
    clientInfo.UpdateSensorInfo(sensorDesc1, pid2, sensorInfo);
    clientInfo.UpdateSensorInfo(sensorDesc2, pid2, sensorInfo);

    // ===== 1. GetActiveInfoList =====
    {
        std::vector<ActiveInfo> activeInfoList = powerPolicy.GetActiveInfoList(pid1);
    }
    {
        std::vector<ActiveInfo> activeInfoList = powerPolicy.GetActiveInfoList(pid2);
    }
    {
        // Non-existent pid
        std::vector<ActiveInfo> activeInfoList = powerPolicy.GetActiveInfoList(99999);
    }

    // ===== 2. SuspendSensors =====
    {
        // First suspend - saves sensor info and disables
        powerPolicy.SuspendSensors(pid1);
    }
    {
        // Suspend again - pidSensorInfoIt already exists path
        powerPolicy.SuspendSensors(pid1);
    }
    {
        // Suspend pid2 - has sensor also used by pid1 (IsOtherClientUsingSensor)
        powerPolicy.SuspendSensors(pid2);
    }
    {
        // Suspend non-existent pid - empty sensorIdList
        powerPolicy.SuspendSensors(99999);
    }

    // ===== 3. ResumeSensors =====
    {
        // Resume pid1 - was suspended
        powerPolicy.ResumeSensors(pid1);
    }
    {
        // Resume pid2
        powerPolicy.ResumeSensors(pid2);
    }
    {
        // Resume non-suspended pid - not in pidSensorInfoMap
        powerPolicy.ResumeSensors(99998);
    }

    // ===== 4. ResetSensors =====
    {
        // Suspend both pids first, then reset
        clientInfo.UpdateSensorInfo(sensorDesc1, pid1, sensorInfo);
        clientInfo.UpdateSensorInfo(sensorDesc1, pid2, sensorInfo);
        powerPolicy.SuspendSensors(pid1);
        powerPolicy.SuspendSensors(pid2);
        powerPolicy.ResetSensors();
    }

    // ===== 5. ReportActiveInfo =====
    {
        ActiveInfo activeInfo(pid1, 0, sensorType, 0, samplingPeriodNs, maxReportDelayNs);
        std::vector<SessionPtr> emptySessionList;
        powerPolicy.ReportActiveInfo(activeInfo, emptySessionList);
    }
    {
        // Invalid activeInfo (negative pid)
        ActiveInfo activeInfo(-1, 0, -1, 0, 0, 0);
        std::vector<SessionPtr> emptySessionList;
        powerPolicy.ReportActiveInfo(activeInfo, emptySessionList);
    }

    // ===== 6. DeleteDeathPidSensorInfo =====
    {
        // Setup suspend info first, then delete
        clientInfo.UpdateSensorInfo(sensorDesc1, pid1, sensorInfo);
        powerPolicy.SuspendSensors(pid1);
        powerPolicy.DeleteDeathPidSensorInfo(pid1);
    }
    {
        // Delete non-existent pid - no-op
        powerPolicy.DeleteDeathPidSensorInfo(99997);
    }

    // ===== 7. GetSuspendPidList =====
    {
        clientInfo.UpdateSensorInfo(sensorDesc1, pid1, sensorInfo);
        clientInfo.UpdateSensorInfo(sensorDesc1, pid2, sensorInfo);
        powerPolicy.SuspendSensors(pid1);
        powerPolicy.SuspendSensors(pid2);
        std::vector<int32_t> suspendList = powerPolicy.GetSuspendPidList();
        // Clean up
        powerPolicy.ResetSensors();
    }

    // ===== 8. CheckFreezingSensor (via Suspend with pedometer) =====
    {
        // Pedometer sensor should be skipped during suspend
        clientInfo.UpdateSensorInfo(sensorDescPedometer, pid1, sensorInfo);
        powerPolicy.SuspendSensors(pid1);
        powerPolicy.ResumeSensors(pid1);
    }

    // Cleanup
    clientInfo.ClearSensorInfo(sensorDesc1);
    clientInfo.ClearSensorInfo(sensorDesc2);
    clientInfo.ClearSensorInfo(sensorDescPedometer);
    clientInfo.DestroySensorChannel(pid1);
    clientInfo.DestroySensorChannel(pid2);

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
    OHOS::Sensors::SensorPowerPolicyFuzzTest(data, size);
    return 0;
}
