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

#include "sensorshakecontrol_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "sensor_shake_control_manager.h"

namespace OHOS {
namespace Sensors {
using namespace Security::AccessToken;
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MAX_STRING_LEN = 64;

struct ShakeControlFuzzInput {
    int32_t userId = 0;
    std::string bundleName;
    std::string tokenId;
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

std::string GetStringFromData(const uint8_t *data, size_t size, size_t maxLen)
{
    size_t len = (size < maxLen) ? size : maxLen;
    if (len == 0) {
        return "";
    }
    return std::string(reinterpret_cast<const char *>(data), len);
}

void ReadFuzzInput(const uint8_t *data, size_t size, ShakeControlFuzzInput &input)
{
    size_t startPos = 0;
    startPos += GetObject<int32_t>(input.userId, data + startPos, size - startPos);

    size_t remaining = size - startPos;
    size_t bundleNameLen = (remaining > MAX_STRING_LEN) ? MAX_STRING_LEN : remaining / 2;
    input.bundleName = GetStringFromData(data + startPos, bundleNameLen, MAX_STRING_LEN);

    startPos += bundleNameLen;
    remaining = size - startPos;
    size_t tokenIdLen = (remaining > MAX_STRING_LEN) ? MAX_STRING_LEN : remaining;
    input.tokenId = GetStringFromData(data + startPos, tokenIdLen, MAX_STRING_LEN);
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
        .processName = "SensorShakeControlFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

void ResetManagerState(const std::shared_ptr<SensorShakeControlManager> &manager)
{
    manager->shakeSensorControlAppInfoList_.clear();
    manager->shakeSensorNoControlAppInfoList_.clear();
    manager->shakeIgnoreControlList_.clear();
}

void RunGetShakeIgnoreControlListTests(const std::shared_ptr<SensorShakeControlManager> &manager,
    const ShakeControlFuzzInput &input)
{
    (void)manager->GetShakeIgnoreControlList("123,456,789", ',');
    (void)manager->GetShakeIgnoreControlList("", ',');
    (void)manager->GetShakeIgnoreControlList("12345", ',');
    (void)manager->GetShakeIgnoreControlList(" 123 , 456 , 789 ", ',');
    (void)manager->GetShakeIgnoreControlList("123,123,456", ',');
    (void)manager->GetShakeIgnoreControlList("   ,   ,   ", ',');
    (void)manager->GetShakeIgnoreControlList("a;b;c", ';');
    (void)manager->GetShakeIgnoreControlList(input.bundleName + "," + input.tokenId, ',');
}

void RunCheckAppIsNeedControlTests(const std::shared_ptr<SensorShakeControlManager> &manager,
    const ShakeControlFuzzInput &input)
{
    ResetManagerState(manager);
    (void)manager->CheckAppIsNeedControl("com.test.app", "100", 0);

    ShakeControlAppInfo controlApp = { "com.test.controlled", "200", input.userId };
    manager->shakeSensorControlAppInfoList_.insert(controlApp);
    (void)manager->CheckAppIsNeedControl("com.test.controlled", "200", input.userId);
    (void)manager->CheckAppIsNeedControl("com.test.other", "300", input.userId);

    manager->shakeIgnoreControlList_.insert("200");
    (void)manager->CheckAppIsNeedControl("com.test.controlled", "200", input.userId);
    (void)manager->CheckAppIsNeedControl("com.test.controlled", "201", input.userId);
    manager->shakeIgnoreControlList_.clear();
    (void)manager->CheckAppIsNeedControl(input.bundleName, input.tokenId, input.userId);
}

void RunCheckAppInfoIsNeedModifyTests(const std::shared_ptr<SensorShakeControlManager> &manager,
    const ShakeControlFuzzInput &input)
{
    ResetManagerState(manager);
    (void)manager->CheckAppInfoIsNeedModify("com.test.app", "100", input.userId);

    ShakeControlAppInfo noControlApp = { "com.test.nocontrol", "400", input.userId };
    manager->shakeSensorNoControlAppInfoList_.insert(noControlApp);
    (void)manager->CheckAppInfoIsNeedModify("com.test.nocontrol", "400", input.userId);
    (void)manager->CheckAppInfoIsNeedModify("com.test.other", "500", input.userId);

    ResetManagerState(manager);
    ShakeControlAppInfo controlApp = { "com.test.controlled2", "600", input.userId };
    manager->shakeSensorControlAppInfoList_.insert(controlApp);
    (void)manager->CheckAppInfoIsNeedModify("com.test.controlled2", "600", input.userId);
    (void)manager->CheckAppInfoIsNeedModify("com.test.new", "700", input.userId);
}

void RunAppInfoAndLogTests(const std::shared_ptr<SensorShakeControlManager> &manager,
    const ShakeControlFuzzInput &input)
{
    ResetManagerState(manager);
    ShakeControlAppInfo controlApp = { "com.test.a", "100", input.userId };
    ShakeControlAppInfo noControlApp = { "com.test.b", "200", input.userId };
    manager->shakeSensorControlAppInfoList_.insert(controlApp);
    manager->shakeSensorNoControlAppInfoList_.insert(noControlApp);
    (void)manager->CheckAppInfoIsNeedModify("com.test.a", "100", input.userId);
    (void)manager->CheckAppInfoIsNeedModify("com.test.b", "200", input.userId);
    (void)manager->CheckAppInfoIsNeedModify("com.test.c", "300", input.userId);
    (void)manager->CheckAppInfoIsNeedModify(input.bundleName, input.tokenId, input.userId);
    (void)manager->GetCurrentUserId();

    std::unordered_set<ShakeControlAppInfo> oldClosed;
    std::unordered_set<ShakeControlAppInfo> latestClosed;
    std::unordered_set<ShakeControlAppInfo> latestOpened;
    ShakeControlAppInfo app1 = { "com.test.app1", "100", input.userId };
    ShakeControlAppInfo app2 = { "com.test.app2", "200", input.userId };
    ShakeControlAppInfo app3 = { "com.test.app3", "300", input.userId };
    oldClosed.insert(app1);
    latestOpened.insert(app1);
    latestClosed.insert(app2);
    oldClosed.insert(app3);
    latestClosed.insert(app3);
    manager->ReportAppSwitchChangeLog(oldClosed, latestClosed, latestOpened);

    std::unordered_set<ShakeControlAppInfo> empty;
    manager->ReportAppSwitchChangeLog(empty, empty, empty);
}
} // namespace

bool SensorShakeControlFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();

    ShakeControlFuzzInput input;
    ReadFuzzInput(data, size, input);

    auto manager = SENSOR_SHAKE_CONTROL_MGR;
    RunGetShakeIgnoreControlListTests(manager, input);
    RunCheckAppIsNeedControlTests(manager, input);
    RunCheckAppInfoIsNeedModifyTests(manager, input);
    RunAppInfoAndLogTests(manager, input);
    ResetManagerState(manager);
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
    OHOS::Sensors::SensorShakeControlFuzzTest(data, size);
    return 0;
}
