/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_UTIL_H
#define PERMISSION_UTIL_H

#include <mutex>
#include <string>
#include <unordered_map>
#include "accesstoken_kit.h"
#include "refbase.h"
#include "singleton.h"

namespace OHOS {
namespace Sensors {
using namespace Security::AccessToken;
class PermissionUtil : public Singleton<PermissionUtil> {
public:
    PermissionUtil() = default;
    virtual ~PermissionUtil() {};
    bool CheckSensorPermission(AccessTokenID callerToken, int32_t sensorTypeId);

private:
    static std::unordered_map<uint32_t, std::string> sensorPermissions_;
};
}  // namespace Sensors
}  // namespace OHOS
#endif  // PERMISSION_UTIL_H
