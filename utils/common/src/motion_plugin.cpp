/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "motion_plugin.h"

#include "sensor_log.h"

#undef LOG_TAG
#define LOG_TAG "MotionPlugin"

namespace OHOS {
namespace Sensors {
namespace {
    constexpr uint32_t SLEEP_TIME_US = 10000;
}

static void *g_handle = nullptr;

bool LoadMotionSensor(void)
{
    SEN_HILOGI("Load motion plugin in");
    if (g_handle != nullptr) {
        SEN_HILOGW("Motion plugin has already exits");
        return true;
    }
    int32_t cnt = 0;
    int32_t retryTimes = 3;
    do {
        cnt++;
        g_handle = dlopen(PLUGIN_SO_PATH.c_str(), RTLD_LAZY);
        SEN_HILOGI("dlopen %{public}s, retry cnt: %{public}d", PLUGIN_SO_PATH.c_str(), cnt);
        usleep(SLEEP_TIME_US);
    } while (!g_handle && cnt < retryTimes);
    return (g_handle != nullptr);
}

void UnloadMotionSensor(void)
{
    SEN_HILOGI("Unload motion plugin in");
    if (g_handle != nullptr) {
        dlclose(g_handle);
        g_handle = nullptr;
    }
}

__attribute__((no_sanitize("cfi"))) void MotionTransformIfRequired(const std::string& pkName,
    uint32_t state, SensorData* sensorData)
{
    if (g_handle == nullptr) {
        return;
    }
    MotionTransformIfRequiredPtr func = (MotionTransformIfRequiredPtr)(dlsym(g_handle, "TransformIfRequired"));
    if (func == nullptr) {
        SEN_HILOGE("func is nullptr");
        return;
    }
    const char* dlsymError = dlerror();
    if  (dlsymError) {
        SEN_HILOGE("dlsym error: %{public}s", dlsymError);
        return;
    }
    return func(pkName, state, sensorData);
}
}
}