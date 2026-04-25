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
#include <vector>

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
constexpr int32_t DEFAULT_PID1 = 1001;
constexpr int32_t DEFAULT_PID2 = 1002;
constexpr int32_t DEFAULT_UID1 = 2001;
constexpr int32_t DEFAULT_UID2 = 2002;
constexpr int32_t DEFAULT_DEVICE_ID = 0;
constexpr int32_t DEFAULT_SENSOR_ID = 0;
constexpr int32_t DEFAULT_LOCATION = 1;
constexpr int32_t PEDOMETER_DETECTION_TYPE = 22;
constexpr int32_t UNKNOWN_PID1 = 99999;
constexpr int32_t UNKNOWN_PID2 = 99998;
constexpr int32_t UNKNOWN_PID3 = 99997;
constexpr int64_t MIN_SAMPLE_PERIOD_NS = 100000;

struct SensorPowerPolicyFuzzInput {
    int32_t pid1 = 0;
    int32_t pid2 = 0;
    int32_t sensorType = 0;
    int64_t samplingPeriodNs = 0;
    int64_t maxReportDelayNs = 0;
    int32_t sensorId2 = 0;
};

struct SensorPowerPolicyTestConfig {
    int32_t pid1 = 0;
    int32_t pid2 = 0;
    int32_t sensorType = 0;
    int64_t samplingPeriodNs = 0;
    int64_t maxReportDelayNs = 0;
    SensorDescription sensorDesc1 {};
    SensorDescription sensorDescPedometer {};
    SensorDescription sensorDesc2 {};
    SensorBasicInfo sensorInfo;
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

void ReadFuzzInput(const uint8_t *data, size_t size, SensorPowerPolicyFuzzInput &input)
{
    size_t startPos = 0;
    startPos += GetObject<int32_t>(input.pid1, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.pid2, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.sensorType, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.samplingPeriodNs, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.maxReportDelayNs, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.sensorId2, data + startPos, size - startPos);
}

void NormalizeInput(SensorPowerPolicyFuzzInput &input)
{
    if (input.pid1 <= 0) {
        input.pid1 = DEFAULT_PID1;
    }
    if (input.pid2 <= 0) {
        input.pid2 = DEFAULT_PID2;
    }
    if (input.samplingPeriodNs <= 0) {
        input.samplingPeriodNs = MIN_SAMPLE_PERIOD_NS;
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
        .processName = "SensorPowerPolicyFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

sptr<SensorBasicDataChannel> CreateChannel(ClientInfo &clientInfo, int32_t pid)
{
    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel != nullptr) {
        channel->CreateSensorBasicChannel();
        channel->SetSensorStatus(true);
        clientInfo.UpdateSensorChannel(pid, channel);
    }
    return channel;
}

void PrepareClientInfoState(ClientInfo &clientInfo, const SensorPowerPolicyTestConfig &config)
{
    clientInfo.UpdateAppThreadInfo(config.pid1, DEFAULT_UID1, 0);
    (void)CreateChannel(clientInfo, config.pid1);
    clientInfo.UpdateSensorInfo(config.sensorDesc1, config.pid1, config.sensorInfo);
    clientInfo.UpdateSensorInfo(config.sensorDescPedometer, config.pid1, config.sensorInfo);

    clientInfo.UpdateAppThreadInfo(config.pid2, DEFAULT_UID2, 0);
    (void)CreateChannel(clientInfo, config.pid2);
    clientInfo.UpdateSensorInfo(config.sensorDesc1, config.pid2, config.sensorInfo);
    clientInfo.UpdateSensorInfo(config.sensorDesc2, config.pid2, config.sensorInfo);
}

void RunActiveInfoTests(SensorPowerPolicy &powerPolicy, int32_t pid1, int32_t pid2)
{
    (void)powerPolicy.GetActiveInfoList(pid1);
    (void)powerPolicy.GetActiveInfoList(pid2);
    (void)powerPolicy.GetActiveInfoList(UNKNOWN_PID1);
}

void RunSuspendResumeTests(SensorPowerPolicy &powerPolicy, int32_t pid1, int32_t pid2)
{
    powerPolicy.SuspendSensors(pid1);
    powerPolicy.SuspendSensors(pid1);
    powerPolicy.SuspendSensors(pid2);
    powerPolicy.SuspendSensors(UNKNOWN_PID1);
    powerPolicy.ResumeSensors(pid1);
    powerPolicy.ResumeSensors(pid2);
    powerPolicy.ResumeSensors(UNKNOWN_PID2);
}

void RunResetAndReportTests(SensorPowerPolicy &powerPolicy, ClientInfo &clientInfo,
    const SensorPowerPolicyTestConfig &config)
{
    clientInfo.UpdateSensorInfo(config.sensorDesc1, config.pid1, config.sensorInfo);
    clientInfo.UpdateSensorInfo(config.sensorDesc1, config.pid2, config.sensorInfo);
    powerPolicy.SuspendSensors(config.pid1);
    powerPolicy.SuspendSensors(config.pid2);
    powerPolicy.ResetSensors();

    ActiveInfo activeInfo(config.pid1, DEFAULT_DEVICE_ID, config.sensorType, DEFAULT_SENSOR_ID,
        config.samplingPeriodNs, config.maxReportDelayNs);
    std::vector<SessionPtr> emptySessionList;
    powerPolicy.ReportActiveInfo(activeInfo, emptySessionList);

    ActiveInfo invalidActiveInfo(-1, DEFAULT_DEVICE_ID, -1, DEFAULT_SENSOR_ID, 0, 0);
    powerPolicy.ReportActiveInfo(invalidActiveInfo, emptySessionList);
}

void RunDeleteAndSuspendListTests(SensorPowerPolicy &powerPolicy, ClientInfo &clientInfo,
    const SensorPowerPolicyTestConfig &config)
{
    clientInfo.UpdateSensorInfo(config.sensorDesc1, config.pid1, config.sensorInfo);
    powerPolicy.SuspendSensors(config.pid1);
    powerPolicy.DeleteDeathPidSensorInfo(config.pid1);
    powerPolicy.DeleteDeathPidSensorInfo(UNKNOWN_PID3);

    clientInfo.UpdateSensorInfo(config.sensorDesc1, config.pid1, config.sensorInfo);
    clientInfo.UpdateSensorInfo(config.sensorDesc1, config.pid2, config.sensorInfo);
    powerPolicy.SuspendSensors(config.pid1);
    powerPolicy.SuspendSensors(config.pid2);
    (void)powerPolicy.GetSuspendPidList();
    powerPolicy.ResetSensors();
}

void RunFreezingSensorTest(SensorPowerPolicy &powerPolicy, ClientInfo &clientInfo,
    const SensorDescription &sensorDescPedometer, const SensorBasicInfo &sensorInfo, int32_t pid1)
{
    clientInfo.UpdateSensorInfo(sensorDescPedometer, pid1, sensorInfo);
    powerPolicy.SuspendSensors(pid1);
    powerPolicy.ResumeSensors(pid1);
}

void CleanupClientInfoState(ClientInfo &clientInfo, const SensorPowerPolicyTestConfig &config)
{
    clientInfo.ClearSensorInfo(config.sensorDesc1);
    clientInfo.ClearSensorInfo(config.sensorDesc2);
    clientInfo.ClearSensorInfo(config.sensorDescPedometer);
    clientInfo.DestroySensorChannel(config.pid1);
    clientInfo.DestroySensorChannel(config.pid2);
}
} // namespace

bool SensorPowerPolicyFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();

    SensorPowerPolicyFuzzInput input;
    ReadFuzzInput(data, size, input);
    NormalizeInput(input);

    SensorPowerPolicy &powerPolicy = SensorPowerPolicy::GetInstance();
    ClientInfo &clientInfo = ClientInfo::GetInstance();
    SensorPowerPolicyTestConfig config;
    config.pid1 = input.pid1;
    config.pid2 = input.pid2;
    config.sensorType = input.sensorType;
    config.samplingPeriodNs = input.samplingPeriodNs;
    config.maxReportDelayNs = input.maxReportDelayNs;
    config.sensorDesc1 = { DEFAULT_DEVICE_ID, input.sensorType, DEFAULT_SENSOR_ID, DEFAULT_LOCATION };
    config.sensorDescPedometer = { DEFAULT_DEVICE_ID, PEDOMETER_DETECTION_TYPE, DEFAULT_SENSOR_ID,
        DEFAULT_LOCATION };
    config.sensorDesc2 = { DEFAULT_DEVICE_ID, input.sensorType + 1, input.sensorId2, DEFAULT_LOCATION };
    config.sensorInfo.SetSamplingPeriodNs(input.samplingPeriodNs);
    config.sensorInfo.SetMaxReportDelayNs(input.maxReportDelayNs);
    config.sensorInfo.SetSensorState(true);
    PrepareClientInfoState(clientInfo, config);
    RunActiveInfoTests(powerPolicy, input.pid1, input.pid2);
    RunSuspendResumeTests(powerPolicy, input.pid1, input.pid2);
    RunResetAndReportTests(powerPolicy, clientInfo, config);
    RunDeleteAndSuspendListTests(powerPolicy, clientInfo, config);
    RunFreezingSensorTest(powerPolicy, clientInfo, config.sensorDescPedometer, config.sensorInfo, input.pid1);
    CleanupClientInfoState(clientInfo, config);
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
