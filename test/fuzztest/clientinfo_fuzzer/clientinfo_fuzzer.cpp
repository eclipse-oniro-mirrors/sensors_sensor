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
#include "sensor_basic_data_channel.h"
#include "sensor_basic_info.h"

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
        .processName = "ClientInfoFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

bool ClientInfoFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();
    ClientInfo &clientInfo = ClientInfo::GetInstance();
    size_t startPos = 0;

    // Fuzz parameters
    int32_t deviceId = 0;
    startPos += GetObject<int32_t>(deviceId, data + startPos, size - startPos);
    int32_t sensorType = 0;
    startPos += GetObject<int32_t>(sensorType, data + startPos, size - startPos);
    int32_t sensorId = 0;
    startPos += GetObject<int32_t>(sensorId, data + startPos, size - startPos);
    int32_t location = 0;
    startPos += GetObject<int32_t>(location, data + startPos, size - startPos);
    int32_t pid = 0;
    startPos += GetObject<int32_t>(pid, data + startPos, size - startPos);
    int32_t uid = 0;
    startPos += GetObject<int32_t>(uid, data + startPos, size - startPos);
    int64_t samplingPeriodNs = 0;
    startPos += GetObject<int64_t>(samplingPeriodNs, data + startPos, size - startPos);
    int64_t maxReportDelayNs = 0;
    startPos += GetObject<int64_t>(maxReportDelayNs, data + startPos, size - startPos);
    int32_t cmdType = 0;
    startPos += GetObject<int32_t>(cmdType, data + startPos, size - startPos);
    uint32_t deviceStatus = 0;
    startPos += GetObject<uint32_t>(deviceStatus, data + startPos, size - startPos);
    int32_t deviceType = 0;
    startPos += GetObject<int32_t>(deviceType, data + startPos, size - startPos);
    AccessTokenID callerToken = 0;
    startPos += GetObject<AccessTokenID>(callerToken, data + startPos, size - startPos);
    bool permState = false;
    startPos += GetObject<bool>(permState, data + startPos, size - startPos);

    SensorDescription sensorDesc {
        .deviceId = deviceId,
        .sensorType = sensorType,
        .sensorId = sensorId,
        .location = location
    };

    SensorDescription sensorDesc2 {
        .deviceId = deviceId + 1,
        .sensorType = sensorType + 1,
        .sensorId = sensorId + 1,
        .location = location
    };

    // 1. GetSensorState - no data yet, should return false
    clientInfo.GetSensorState(sensorDesc);

    // 2. UpdateAppThreadInfo
    clientInfo.UpdateAppThreadInfo(pid, uid, callerToken);
    clientInfo.UpdateAppThreadInfo(pid + 1, uid + 1, callerToken + 1);

    // 3. UpdateSensorChannel - create channel and associate with pid
    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel != nullptr) {
        clientInfo.UpdateSensorChannel(pid, channel);
    }
    sptr<SensorBasicDataChannel> channel2 = new (std::nothrow) SensorBasicDataChannel();
    if (channel2 != nullptr) {
        clientInfo.UpdateSensorChannel(pid + 1, channel2);
    }

    // 4. UpdateSensorInfo - enable sensor for pid
    SensorBasicInfo sensorInfo;
    sensorInfo.SetSamplingPeriodNs(samplingPeriodNs);
    sensorInfo.SetMaxReportDelayNs(maxReportDelayNs);
    sensorInfo.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc, pid, sensorInfo);

    // Also add a second pid for same sensor
    SensorBasicInfo sensorInfo2;
    sensorInfo2.SetSamplingPeriodNs(samplingPeriodNs + 100000);
    sensorInfo2.SetMaxReportDelayNs(maxReportDelayNs + 100000);
    sensorInfo2.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc, pid + 1, sensorInfo2);

    // Add second sensor desc for pid
    clientInfo.UpdateSensorInfo(sensorDesc2, pid, sensorInfo);

    // 5. GetSensorState - now should find state
    clientInfo.GetSensorState(sensorDesc);
    clientInfo.GetSensorState(sensorDesc2);

    // 6. GetBestSensorInfo
    clientInfo.GetBestSensorInfo(sensorDesc);

    // 7. GetCurPidSensorInfo
    clientInfo.GetCurPidSensorInfo(sensorDesc, pid);
    clientInfo.GetCurPidSensorInfo(sensorDesc, pid + 1);

    // 8. OnlyCurPidSensorEnabled
    clientInfo.OnlyCurPidSensorEnabled(sensorDesc, pid);
    clientInfo.OnlyCurPidSensorEnabled(sensorDesc2, pid);

    // 9. GetSensorChannel
    clientInfo.GetSensorChannel(sensorDesc);

    // 10. GetSensorChannelByPid
    clientInfo.GetSensorChannelByPid(pid);
    clientInfo.GetSensorChannelByPid(-1);  // invalid pid

    // 11. GetSensorChannelByUid
    clientInfo.GetSensorChannelByUid(uid);
    clientInfo.GetSensorChannelByUid(-1);  // invalid uid

    // 12. ComputeBestPeriodCount & ComputeBestFifoCount
    if (channel != nullptr) {
        clientInfo.ComputeBestPeriodCount(sensorDesc, channel);
        clientInfo.ComputeBestFifoCount(sensorDesc, channel);
    }

    // 13. GetAppInfoByChannel
    if (channel != nullptr) {
        clientInfo.GetAppInfoByChannel(channel);
    }
    clientInfo.GetAppInfoByChannel(nullptr);  // null channel

    // 14. GetSensorChannelInfo
    std::vector<SensorChannelInfo> channelInfoVec;
    clientInfo.GetSensorChannelInfo(channelInfoVec);

    // 15. GetUidByPid / GetTokenIdByPid / GetPidByTokenId
    clientInfo.GetUidByPid(pid);
    clientInfo.GetUidByPid(-1);
    clientInfo.GetTokenIdByPid(pid);
    clientInfo.GetPidByTokenId(callerToken);

    // 16. UpdateCmd / GetCmdList / DestroyCmd
    clientInfo.UpdateCmd(sensorType, uid, cmdType);
    clientInfo.UpdateCmd(sensorType, uid, cmdType + 1);
    clientInfo.UpdateCmd(sensorType + 1, uid, cmdType);

    // 17. UpdateDataQueue / GetDumpQueue / ClearDataQueue
    SensorData sensorData;
    (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
    sensorData.sensorTypeId = sensorType;
    sensorData.deviceId = deviceId;
    sensorData.sensorId = sensorId;
    sensorData.location = location;
    sensorData.dataLen = sizeof(float);
    float testVal = 1.0f;
    errno_t cpRet = memcpy_s(sensorData.data, sizeof(sensorData.data), &testVal, sizeof(float));
    if (cpRet == EOK) {
        clientInfo.UpdateDataQueue(sensorType, sensorData);
        // Update multiple times to test queue overflow
        for (int i = 0; i < 12; i++) {
            sensorData.timestamp = i;
            clientInfo.UpdateDataQueue(sensorType, sensorData);
        }
    }
    clientInfo.GetDumpQueue();
    clientInfo.ClearDataQueue(sensorDesc);

    // 18. StoreEvent / GetStoreEvent / ClearEvent
    if (cpRet == EOK) {
        clientInfo.StoreEvent(sensorData);
        SensorData outData;
        clientInfo.GetStoreEvent(sensorDesc, outData);
    }

    // 19. AddActiveInfoCBPid / GetActiveInfoCBPid / DelActiveInfoCBPid
    clientInfo.AddActiveInfoCBPid(pid);
    clientInfo.AddActiveInfoCBPid(pid);  // duplicate
    clientInfo.AddActiveInfoCBPid(pid + 1);
    clientInfo.GetActiveInfoCBPid();
    clientInfo.DelActiveInfoCBPid(pid);
    clientInfo.DelActiveInfoCBPid(pid + 100);  // non-existent

    // 20. CallingService
    clientInfo.CallingService(pid);
    clientInfo.CallingService(pid + 100);

    // 21. SetDeviceStatus / GetDeviceStatus
    clientInfo.SetDeviceStatus(deviceStatus);
    clientInfo.GetDeviceStatus();

    // 22. SetDeviceType / GetDeviceType
    clientInfo.SetDeviceType(deviceType);
    clientInfo.GetDeviceType();

    // 23. IsSubscribe
    clientInfo.IsSubscribe();

    // 24. UpdatePermState / ChangeSensorPerm
    clientInfo.UpdatePermState(pid, sensorType, permState);
    clientInfo.ChangeSensorPerm(callerToken, "ohos.permission.ACTIVITY_MOTION", permState);
    clientInfo.ChangeSensorPerm(callerToken, "ohos.permission.READ_HEALTH_DATA", permState);
    clientInfo.ChangeSensorPerm(callerToken, "invalid.permission", permState);

    // 25. GetSensorIdByPid
    clientInfo.GetSensorIdByPid(pid);

    // 26. RemoveSubscriber
    clientInfo.RemoveSubscriber(sensorDesc, pid + 1);

    // 27. ClearCurPidSensorInfo
    clientInfo.ClearCurPidSensorInfo(sensorDesc2, pid);

    // 28. ClearSensorInfo
    clientInfo.ClearSensorInfo(sensorDesc2);

    // 29. DestroyCmd
    clientInfo.DestroyCmd(uid);

    // 30. ClearEvent
    clientInfo.ClearEvent();

    // 31. DestroySensorChannel - cleanup
    clientInfo.DestroySensorChannel(pid);
    clientInfo.DestroySensorChannel(pid + 1);

    // 32. DestroyAppThreadInfo - cleanup (already called inside DestroySensorChannel)
    clientInfo.DestroyAppThreadInfo(pid);

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
