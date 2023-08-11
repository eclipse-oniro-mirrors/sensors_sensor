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
#include "hdi_service_impl.h"

#include <cmath>
#include <random>
#include <thread>
#include <unistd.h>

#include "sensors_errors.h"

namespace OHOS {
namespace Sensors {
using namespace OHOS::HiviewDFX;

namespace {
constexpr HiLogLabel LABEL = { LOG_CORE, SENSOR_LOG_DOMAIN, "HdiServiceImpl" };
constexpr int64_t SAMPLING_INTERVAL_NS = 200000000;
constexpr int32_t CONVERT_MULTIPLES = 1000;
constexpr float TARGET_SUM = 9.8 * 9.8;
constexpr float MAX_RANGE = 9999.0;
constexpr float MAX_ANGLE = 180.0;
std::vector<SensorInfo> g_sensorInfos = {
    {"sensor_test", "default", "1.0.0", "1.0.0", 0, 1, 9999.0, 0.000001, 23.0, 100000000, 1000000000},
};
std::vector<int32_t> g_supportSensors = {
    SENSOR_TYPE_ID_ACCELEROMETER,
    SENSOR_TYPE_ID_COLOR,
    SENSOR_TYPE_ID_SAR,
    SENSOR_TYPE_ID_POSTURE
};
SensorEvent g_accEvent = {
    .sensorTypeId = SENSOR_TYPE_ID_ACCELEROMETER,
    .dataLen = 12
};
SensorEvent g_colorEvent = {
    .sensorTypeId = SENSOR_TYPE_ID_COLOR,
    .dataLen = 8
};
SensorEvent g_sarEvent = {
    .sensorTypeId = SENSOR_TYPE_ID_SAR,
    .dataLen = 4
};
SensorEvent g_postureEvent = {
    .sensorTypeId = SENSOR_TYPE_ID_POSTURE,
    .dataLen = 28
};
}
std::vector<int32_t> HdiServiceImpl::enableSensors_;
std::vector<RecordSensorCallback> HdiServiceImpl::callbacks_;
int64_t HdiServiceImpl::samplingInterval_ = -1;
int64_t HdiServiceImpl::reportInterval_ = -1;
std::atomic_bool HdiServiceImpl::isStop_ = false;

void HdiServiceImpl::GenerateEvent()
{
    for (const auto &sensorId : enableSensors_) {
        switch (sensorId) {
            case SENSOR_TYPE_ID_ACCELEROMETER:
                GenerateAccelerometerEvent(&g_accEvent);
                break;
            case SENSOR_TYPE_ID_COLOR:
                GenerateColorEvent(&g_colorEvent);
                break;
            case SENSOR_TYPE_ID_SAR:
                GenerateSarEvent(&g_sarEvent);
                break;
            case SENSOR_TYPE_ID_POSTURE:
                GeneratePostureEvent(&g_postureEvent);
                break;
            default:
                SEN_HILOGW("sensorId:%{public}d", sensorId);
                break;
        }
    }
}

void HdiServiceImpl::GenerateAccelerometerEvent(SensorEvent *event)
{
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_real_distribution<float> distr(0, TARGET_SUM);
    float num1 = distr(eng);
    float num2 = distr(eng);
    if (num1 > num2) {
        float temp = num1;
        num1 = num2;
        num2 = temp;
    }
    float accData[3];
    accData[0] = sqrt(num1);
    accData[1] = sqrt(num2 - num1);
    accData[2] = sqrt(TARGET_SUM - num2);
    event->data = reinterpret_cast<uint8_t *>(accData);
}

void HdiServiceImpl::GenerateColorEvent(SensorEvent *event)
{
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_real_distribution<float> distr(0, MAX_RANGE);
    float colorData[2];
    colorData[0] = distr(eng);
    colorData[1] = distr(eng);
    event->data = reinterpret_cast<uint8_t *>(colorData);
}

void HdiServiceImpl::GenerateSarEvent(SensorEvent *event)
{
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_real_distribution<float> distr(0, MAX_RANGE);
    float sarData[1];
    sarData[0] = distr(eng);
    event->data = reinterpret_cast<uint8_t *>(sarData);
}

void HdiServiceImpl::GeneratePostureEvent(SensorEvent *event)
{
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_real_distribution<float> distr1(0, TARGET_SUM);
    float num1 = distr1(eng);
    float num2 = distr1(eng);
    if (num1 > num2) {
        float temp = num1;
        num1 = num2;
        num2 = temp;
    }
    float postureData[7];
    postureData[0] = static_cast<float>(sqrt(num1));
    postureData[1] = static_cast<float>(sqrt(num2 - num1));
    postureData[2] = static_cast<float>(sqrt(TARGET_SUM - num2));
    postureData[3] = postureData[0];
    postureData[4] = postureData[1];
    postureData[5] = postureData[2];
    std::uniform_real_distribution<float> distr2(0, MAX_ANGLE);
    postureData[6] = distr2(eng);
    event->data = reinterpret_cast<uint8_t *>(postureData);
}

int32_t HdiServiceImpl::GetSensorList(std::vector<SensorInfo>& sensorList)
{
    CALL_LOG_ENTER;
    sensorList.assign(g_sensorInfos.begin(), g_sensorInfos.end());
    return ERR_OK;
}

void HdiServiceImpl::DataReportThread()
{
    CALL_LOG_ENTER;
    while (true) {
        GenerateEvent();
        usleep(samplingInterval_ / CONVERT_MULTIPLES);
        for (const auto &it : callbacks_) {
            if (it == nullptr) {
                SEN_HILOGW("RecordSensorCallback is null");
                continue;
            }
            for (const auto &sensorId : enableSensors_) {
                switch (sensorId) {
                    case SENSOR_TYPE_ID_ACCELEROMETER:
                        it(&g_accEvent);
                        break;
                    case SENSOR_TYPE_ID_COLOR:
                        it(&g_colorEvent);
                        break;
                    case SENSOR_TYPE_ID_SAR:
                        it(&g_sarEvent);
                        break;
                    case SENSOR_TYPE_ID_POSTURE:
                        it(&g_postureEvent);
                        break;
                    default:
                        SEN_HILOGW("sensorId:%{public}d", sensorId);
                        break;
                }
            }
        }
        if (isStop_) {
            break;
        }
    }
    SEN_HILOGI("Thread stop");
    return;
}

int32_t HdiServiceImpl::EnableSensor(int32_t sensorId)
{
    CALL_LOG_ENTER;
    if (std::find(g_supportSensors.begin(), g_supportSensors.end(), sensorId) == g_supportSensors.end()) {
        SEN_HILOGE("Not support enable sensorId:%{public}d", sensorId);
        return ERR_NO_INIT;
    }
    if (std::find(enableSensors_.begin(), enableSensors_.end(), sensorId) != enableSensors_.end()) {
        SEN_HILOGI("sensorId:%{public}d has been enabled", sensorId);
        return ERR_OK;
    }
    enableSensors_.push_back(sensorId);
    if (!dataReportThread_.joinable() || isStop_) {
        if (dataReportThread_.joinable()) {
            dataReportThread_.join();
        }
        std::thread senocdDataThread(HdiServiceImpl::DataReportThread);
        dataReportThread_ = std::move(senocdDataThread);
        isStop_ = false;
    }
    return ERR_OK;
};

int32_t HdiServiceImpl::DisableSensor(int32_t sensorId)
{
    CALL_LOG_ENTER;
    if (std::find(g_supportSensors.begin(), g_supportSensors.end(), sensorId) == g_supportSensors.end()) {
        SEN_HILOGE("Not support disable sensorId:%{public}d", sensorId);
        return ERR_NO_INIT;
    }
    if (std::find(enableSensors_.begin(), enableSensors_.end(), sensorId) == enableSensors_.end()) {
        SEN_HILOGE("sensorId:%{public}d should be enable first", sensorId);
        return ERR_NO_INIT;
    }
    std::vector<int32_t>::iterator iter;
    for (iter = enableSensors_.begin(); iter != enableSensors_.end();) {
        if (*iter == sensorId) {
            iter = enableSensors_.erase(iter);
            break;
        } else {
            ++iter;
        }
    }
    if (enableSensors_.empty()) {
        isStop_ = true;
    }
    return ERR_OK;
}

int32_t HdiServiceImpl::SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval)
{
    CALL_LOG_ENTER;
    if (samplingInterval < 0 || reportInterval < 0) {
        samplingInterval = SAMPLING_INTERVAL_NS;
        reportInterval = 0;
    }
    samplingInterval_ = samplingInterval;
    reportInterval_ = reportInterval;
    return ERR_OK;
}

int32_t HdiServiceImpl::SetMode(int32_t sensorId, int32_t mode)
{
    return ERR_OK;
}

int32_t HdiServiceImpl::Register(RecordSensorCallback cb)
{
    CHKPR(cb, ERROR);
    callbacks_.push_back(cb);
    return ERR_OK;
}

int32_t HdiServiceImpl::Unregister()
{
    isStop_ = true;
    return ERR_OK;
}
}  // namespace Sensors
}  // namespace OHOS