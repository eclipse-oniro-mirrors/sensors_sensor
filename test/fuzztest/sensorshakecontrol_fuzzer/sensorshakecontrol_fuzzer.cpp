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

#include "sensorshakecontrol_fuzzer.h"

#include <cstddef>
#include <cstdint>
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

std::string GetStringFromData(const uint8_t *data, size_t size, size_t maxLen)
{
    size_t len = (size < maxLen) ? size : maxLen;
    if (len == 0) {
        return "";
    }
    return std::string(reinterpret_cast<const char *>(data), len);
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

bool SensorShakeControlFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();
    size_t startPos = 0;

    int32_t userId = 0;
    startPos += GetObject<int32_t>(userId, data + startPos, size - startPos);

    // Extract fuzzed strings for bundleName and tokenId
    size_t remaining = size - startPos;
    size_t strLen1 = (remaining > MAX_STRING_LEN) ? MAX_STRING_LEN : remaining / 2;
    std::string bundleName = GetStringFromData(data + startPos, strLen1, MAX_STRING_LEN);
    startPos += strLen1;
    remaining = size - startPos;
    size_t strLen2 = (remaining > MAX_STRING_LEN) ? MAX_STRING_LEN : remaining;
    std::string tokenId = GetStringFromData(data + startPos, strLen2, MAX_STRING_LEN);

    auto mgr = SENSOR_SHAKE_CONTROL_MGR;

    // ===== 1. GetShakeIgnoreControlList =====
    // Normal comma-separated string
    {
        std::unordered_set<std::string> result = mgr->GetShakeIgnoreControlList("123,456,789", ',');
    }
    // Empty string
    {
        std::unordered_set<std::string> result = mgr->GetShakeIgnoreControlList("", ',');
    }
    // Single element
    {
        std::unordered_set<std::string> result = mgr->GetShakeIgnoreControlList("12345", ',');
    }
    // With spaces (trimming path)
    {
        std::unordered_set<std::string> result = mgr->GetShakeIgnoreControlList(" 123 , 456 , 789 ", ',');
    }
    // Duplicate entries
    {
        std::unordered_set<std::string> result = mgr->GetShakeIgnoreControlList("123,123,456", ',');
    }
    // All spaces
    {
        std::unordered_set<std::string> result = mgr->GetShakeIgnoreControlList("   ,   ,   ", ',');
    }
    // Different delimiter
    {
        std::unordered_set<std::string> result = mgr->GetShakeIgnoreControlList("a;b;c", ';');
    }
    // Fuzzed string
    {
        std::string fuzzStr = bundleName + "," + tokenId;
        std::unordered_set<std::string> result = mgr->GetShakeIgnoreControlList(fuzzStr, ',');
    }

    // ===== 2. CheckAppIsNeedControl =====
    // First populate the internal lists via direct member access (-Dprivate=public)
    {
        // Empty control lists - should return false
        mgr->shakeSensorControlAppInfoList_.clear();
        mgr->shakeSensorNoControlAppInfoList_.clear();
        mgr->shakeIgnoreControlList_.clear();

        bool result = mgr->CheckAppIsNeedControl("com.test.app", "100", 0);
        (void)result;
    }
    {
        // Add app to control list - should return true
        ShakeControlAppInfo controlApp = {"com.test.controlled", "200", userId};
        mgr->shakeSensorControlAppInfoList_.clear();
        mgr->shakeSensorControlAppInfoList_.insert(controlApp);

        bool result = mgr->CheckAppIsNeedControl("com.test.controlled", "200", userId);
        (void)result;

        // Different app - not in control list
        result = mgr->CheckAppIsNeedControl("com.test.other", "300", userId);
        (void)result;
    }
    {
        // Add tokenId to ignore list - should return false even if in control list
        mgr->shakeIgnoreControlList_.clear();
        mgr->shakeIgnoreControlList_.insert("200");

        bool result = mgr->CheckAppIsNeedControl("com.test.controlled", "200", userId);
        (void)result;

        // Not in ignore list
        result = mgr->CheckAppIsNeedControl("com.test.controlled", "201", userId);
        (void)result;

        mgr->shakeIgnoreControlList_.clear();
    }
    {
        // Fuzzed inputs
        bool result = mgr->CheckAppIsNeedControl(bundleName, tokenId, userId);
        (void)result;
    }

    // ===== 3. CheckAppInfoIsNeedModify =====
    {
        // Empty lists - should return true (needs modify)
        mgr->shakeSensorControlAppInfoList_.clear();
        mgr->shakeSensorNoControlAppInfoList_.clear();

        bool result = mgr->CheckAppInfoIsNeedModify("com.test.app", "100", userId);
        (void)result;
    }
    {
        // App in no-control list - should return false
        ShakeControlAppInfo noControlApp = {"com.test.nocontrol", "400", userId};
        mgr->shakeSensorNoControlAppInfoList_.clear();
        mgr->shakeSensorNoControlAppInfoList_.insert(noControlApp);

        bool result = mgr->CheckAppInfoIsNeedModify("com.test.nocontrol", "400", userId);
        (void)result;

        // Different app - not in no-control list
        result = mgr->CheckAppInfoIsNeedModify("com.test.other", "500", userId);
        (void)result;
    }
    {
        // App in control list - should return false
        ShakeControlAppInfo controlApp = {"com.test.controlled2", "600", userId};
        mgr->shakeSensorControlAppInfoList_.clear();
        mgr->shakeSensorControlAppInfoList_.insert(controlApp);
        mgr->shakeSensorNoControlAppInfoList_.clear();

        bool result = mgr->CheckAppInfoIsNeedModify("com.test.controlled2", "600", userId);
        (void)result;

        // Different app - not in either list
        result = mgr->CheckAppInfoIsNeedModify("com.test.new", "700", userId);
        (void)result;
    }
    {
        // Both lists populated
        ShakeControlAppInfo controlApp = {"com.test.a", "100", userId};
        ShakeControlAppInfo noControlApp = {"com.test.b", "200", userId};
        mgr->shakeSensorControlAppInfoList_.clear();
        mgr->shakeSensorControlAppInfoList_.insert(controlApp);
        mgr->shakeSensorNoControlAppInfoList_.clear();
        mgr->shakeSensorNoControlAppInfoList_.insert(noControlApp);

        mgr->CheckAppInfoIsNeedModify("com.test.a", "100", userId);
        mgr->CheckAppInfoIsNeedModify("com.test.b", "200", userId);
        mgr->CheckAppInfoIsNeedModify("com.test.c", "300", userId);
    }
    {
        // Fuzzed inputs
        mgr->CheckAppInfoIsNeedModify(bundleName, tokenId, userId);
    }

    // ===== 4. GetCurrentUserId =====
    {
        mgr->GetCurrentUserId();
    }

    // ===== 5. ReportAppSwitchChangeLog =====
    {
        std::unordered_set<ShakeControlAppInfo> oldClosed;
        std::unordered_set<ShakeControlAppInfo> latestClosed;
        std::unordered_set<ShakeControlAppInfo> latestOpened;

        ShakeControlAppInfo app1 = {"com.test.app1", "100", userId};
        ShakeControlAppInfo app2 = {"com.test.app2", "200", userId};
        ShakeControlAppInfo app3 = {"com.test.app3", "300", userId};

        // App moved from closed to opened
        oldClosed.insert(app1);
        latestOpened.insert(app1);
        // App newly closed
        latestClosed.insert(app2);
        // App stayed closed
        oldClosed.insert(app3);
        latestClosed.insert(app3);

        mgr->ReportAppSwitchChangeLog(oldClosed, latestClosed, latestOpened);
    }
    {
        // Empty sets
        std::unordered_set<ShakeControlAppInfo> empty;
        mgr->ReportAppSwitchChangeLog(empty, empty, empty);
    }

    // Cleanup
    mgr->shakeSensorControlAppInfoList_.clear();
    mgr->shakeSensorNoControlAppInfoList_.clear();
    mgr->shakeIgnoreControlList_.clear();

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
