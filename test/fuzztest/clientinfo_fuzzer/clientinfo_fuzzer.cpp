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

#include "clientinfo_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "client_info.h"
#include "permission_util.h"
#include "sensor_basic_data_channel.h"
#include "sensor_basic_info.h"

namespace OHOS {
namespace Sensors {
using namespace Security::AccessToken;
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t NEXT_ENTITY_OFFSET = 1;
constexpr int32_t ABSENT_PID_OFFSET = 100;
constexpr int32_t INVALID_PID = -1;
constexpr int32_t DATA_QUEUE_REPEAT_COUNT = 12;
constexpr int64_t SENSOR_INFO_PERIOD_OFFSET_NS = 100000;
constexpr float TEST_DATA_VALUE = 1.0f;

struct ClientInfoFuzzInput {
    int32_t deviceId = 0;
    int32_t sensorType = 0;
    int32_t sensorId = 0;
    int32_t location = 0;
    int32_t pid = 0;
    int32_t uid = 0;
    int64_t samplingPeriodNs = 0;
    int64_t maxReportDelayNs = 0;
    int32_t cmdType = 0;
    uint32_t deviceStatus = 0;
    int32_t deviceType = 0;
    AccessTokenID callerToken = 0;
    bool permState = false;
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

void ReadFuzzInput(const uint8_t *data, size_t size, ClientInfoFuzzInput &input)
{
    size_t startPos = 0;
    startPos += GetObject<int32_t>(input.deviceId, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.sensorType, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.sensorId, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.location, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.pid, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.uid, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.samplingPeriodNs, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.maxReportDelayNs, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.cmdType, data + startPos, size - startPos);
    startPos += GetObject<uint32_t>(input.deviceStatus, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.deviceType, data + startPos, size - startPos);
    startPos += GetObject<AccessTokenID>(input.callerToken, data + startPos, size - startPos);
    startPos += GetObject<bool>(input.permState, data + startPos, size - startPos);
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
        .processName = "ClientInfoFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

SensorDescription BuildSensorDesc(const ClientInfoFuzzInput &input)
{
    SensorDescription sensorDesc {
        .deviceId = input.deviceId,
        .sensorType = input.sensorType,
        .sensorId = input.sensorId,
        .location = input.location
    };
    return sensorDesc;
}

SensorDescription BuildRelatedSensorDesc(const ClientInfoFuzzInput &input)
{
    SensorDescription sensorDesc {
        .deviceId = input.deviceId + NEXT_ENTITY_OFFSET,
        .sensorType = input.sensorType + NEXT_ENTITY_OFFSET,
        .sensorId = input.sensorId + NEXT_ENTITY_OFFSET,
        .location = input.location
    };
    return sensorDesc;
}

sptr<SensorBasicDataChannel> CreateChannel(ClientInfo &clientInfo, int32_t pid)
{
    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel != nullptr) {
        clientInfo.UpdateSensorChannel(pid, channel);
    }
    return channel;
}

void PrepareClientInfoState(ClientInfo &clientInfo, const ClientInfoFuzzInput &input,
    const SensorDescription &sensorDesc, const SensorDescription &sensorDesc2)
{
    clientInfo.UpdateAppThreadInfo(input.pid, input.uid, input.callerToken);
    clientInfo.UpdateAppThreadInfo(input.pid + NEXT_ENTITY_OFFSET, input.uid + NEXT_ENTITY_OFFSET,
        input.callerToken + NEXT_ENTITY_OFFSET);

    (void)CreateChannel(clientInfo, input.pid);
    (void)CreateChannel(clientInfo, input.pid + NEXT_ENTITY_OFFSET);

    SensorBasicInfo sensorInfo;
    sensorInfo.SetSamplingPeriodNs(input.samplingPeriodNs);
    sensorInfo.SetMaxReportDelayNs(input.maxReportDelayNs);
    sensorInfo.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc, input.pid, sensorInfo);

    SensorBasicInfo sensorInfo2;
    sensorInfo2.SetSamplingPeriodNs(input.samplingPeriodNs + SENSOR_INFO_PERIOD_OFFSET_NS);
    sensorInfo2.SetMaxReportDelayNs(input.maxReportDelayNs + SENSOR_INFO_PERIOD_OFFSET_NS);
    sensorInfo2.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc, input.pid + NEXT_ENTITY_OFFSET, sensorInfo2);
    clientInfo.UpdateSensorInfo(sensorDesc2, input.pid, sensorInfo);
}

void RunInitialStateTests(ClientInfo &clientInfo, const SensorDescription &sensorDesc)
{
    clientInfo.GetSensorState(sensorDesc);
}

void RunSubscriptionTests(ClientInfo &clientInfo, const ClientInfoFuzzInput &input,
    const SensorDescription &sensorDesc, const SensorDescription &sensorDesc2)
{
    clientInfo.GetSensorState(sensorDesc);
    clientInfo.GetSensorState(sensorDesc2);
    clientInfo.GetBestSensorInfo(sensorDesc);
    clientInfo.GetCurPidSensorInfo(sensorDesc, input.pid);
    clientInfo.GetCurPidSensorInfo(sensorDesc, input.pid + NEXT_ENTITY_OFFSET);
    clientInfo.OnlyCurPidSensorEnabled(sensorDesc, input.pid);
    clientInfo.OnlyCurPidSensorEnabled(sensorDesc2, input.pid);
    clientInfo.GetSensorChannel(sensorDesc);
    clientInfo.GetSensorChannelByPid(input.pid);
    clientInfo.GetSensorChannelByPid(INVALID_PID);
    clientInfo.GetSensorChannelByUid(input.uid);
    clientInfo.GetSensorChannelByUid(INVALID_PID);
}

void RunChannelAndCommandTests(ClientInfo &clientInfo, const ClientInfoFuzzInput &input,
    const SensorDescription &sensorDesc)
{
    sptr<SensorBasicDataChannel> channel = clientInfo.GetSensorChannelByPid(input.pid);
    if (channel != nullptr) {
        clientInfo.ComputeBestPeriodCount(sensorDesc, channel);
        clientInfo.ComputeBestFifoCount(sensorDesc, channel);
        clientInfo.GetAppInfoByChannel(channel);
    }
    clientInfo.GetAppInfoByChannel(nullptr);

    std::vector<SensorChannelInfo> channelInfoVec;
    clientInfo.GetSensorChannelInfo(channelInfoVec);
    clientInfo.GetUidByPid(input.pid);
    clientInfo.GetUidByPid(INVALID_PID);
    clientInfo.GetTokenIdByPid(input.pid);
    clientInfo.GetPidByTokenId(input.callerToken);
    clientInfo.UpdateCmd(input.sensorType, input.uid, input.cmdType);
    clientInfo.UpdateCmd(input.sensorType, input.uid, input.cmdType + NEXT_ENTITY_OFFSET);
    clientInfo.UpdateCmd(input.sensorType + NEXT_ENTITY_OFFSET, input.uid, input.cmdType);
}

SensorData MakeSensorData(const ClientInfoFuzzInput &input, errno_t &copyResult)
{
    SensorData sensorData;
    (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
    sensorData.sensorTypeId = input.sensorType;
    sensorData.deviceId = input.deviceId;
    sensorData.sensorId = input.sensorId;
    sensorData.location = input.location;
    sensorData.dataLen = sizeof(float);
    copyResult = memcpy_s(sensorData.data, sizeof(sensorData.data), &TEST_DATA_VALUE, sizeof(float));
    if (copyResult != EOK) {
        sensorData.dataLen = 0;
    }
    return sensorData;
}

void RunQueueAndEventTests(ClientInfo &clientInfo, const SensorDescription &sensorDesc,
    int32_t sensorType, SensorData &sensorData, errno_t copyResult)
{
    if (copyResult == EOK) {
        clientInfo.UpdateDataQueue(sensorType, sensorData);
        for (int32_t index = 0; index < DATA_QUEUE_REPEAT_COUNT; ++index) {
            sensorData.timestamp = index;
            clientInfo.UpdateDataQueue(sensorType, sensorData);
        }
        clientInfo.StoreEvent(sensorData);
        SensorData outData;
        clientInfo.GetStoreEvent(sensorDesc, outData);
    }
    clientInfo.GetDumpQueue();
    clientInfo.ClearDataQueue(sensorDesc);
}

void RunStateAndPermissionTests(ClientInfo &clientInfo, const ClientInfoFuzzInput &input)
{
    clientInfo.AddActiveInfoCBPid(input.pid);
    clientInfo.AddActiveInfoCBPid(input.pid);
    clientInfo.AddActiveInfoCBPid(input.pid + NEXT_ENTITY_OFFSET);
    clientInfo.GetActiveInfoCBPid();
    clientInfo.DelActiveInfoCBPid(input.pid);
    clientInfo.DelActiveInfoCBPid(input.pid + ABSENT_PID_OFFSET);
    clientInfo.CallingService(input.pid);
    clientInfo.CallingService(input.pid + ABSENT_PID_OFFSET);
    clientInfo.SetDeviceStatus(input.deviceStatus);
    clientInfo.GetDeviceStatus();
    clientInfo.SetDeviceType(input.deviceType);
    clientInfo.GetDeviceType();
    clientInfo.IsSubscribe();
    clientInfo.UpdatePermState(input.pid, input.sensorType, input.permState);
    clientInfo.ChangeSensorPerm(input.callerToken, READ_HEALTH_DATA_PERMISSION, input.permState);
    clientInfo.ChangeSensorPerm(input.callerToken, "invalid.permission", input.permState);
}

void CleanupClientInfo(ClientInfo &clientInfo, const SensorDescription &sensorDesc,
    const SensorDescription &sensorDesc2, int32_t pid, int32_t uid)
{
    clientInfo.GetSensorIdByPid(pid);
    clientInfo.RemoveSubscriber(sensorDesc, pid + NEXT_ENTITY_OFFSET);
    clientInfo.ClearCurPidSensorInfo(sensorDesc2, pid);
    clientInfo.ClearSensorInfo(sensorDesc2);
    clientInfo.DestroyCmd(uid);
    clientInfo.ClearEvent();
    clientInfo.DestroySensorChannel(pid);
    clientInfo.DestroySensorChannel(pid + NEXT_ENTITY_OFFSET);
    clientInfo.DestroyAppThreadInfo(pid);
}
} // namespace

bool ClientInfoFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();
    ClientInfo &clientInfo = ClientInfo::GetInstance();

    ClientInfoFuzzInput input;
    ReadFuzzInput(data, size, input);

    SensorDescription sensorDesc = BuildSensorDesc(input);
    SensorDescription sensorDesc2 = BuildRelatedSensorDesc(input);
    RunInitialStateTests(clientInfo, sensorDesc);
    PrepareClientInfoState(clientInfo, input, sensorDesc, sensorDesc2);
    RunSubscriptionTests(clientInfo, input, sensorDesc, sensorDesc2);
    RunChannelAndCommandTests(clientInfo, input, sensorDesc);

    errno_t copyResult = EOK;
    SensorData sensorData = MakeSensorData(input, copyResult);
    RunQueueAndEventTests(clientInfo, sensorDesc, input.sensorType, sensorData, copyResult);
    RunStateAndPermissionTests(clientInfo, input);
    CleanupClientInfo(clientInfo, sensorDesc, sensorDesc2, input.pid, input.uid);
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
    OHOS::Sensors::ClientInfoFuzzTest(data, size);
    return 0;
}
