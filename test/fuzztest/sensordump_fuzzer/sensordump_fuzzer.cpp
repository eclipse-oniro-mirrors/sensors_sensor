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

#include "sensordump_fuzzer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "client_info.h"
#include "sensor.h"
#include "sensor_basic_data_channel.h"
#include "sensor_basic_info.h"
#include "sensor_dump.h"

namespace OHOS {
namespace Sensors {
using namespace Security::AccessToken;
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t TEST_PID = 1000;
constexpr int32_t TEST_UID = 2000;
constexpr int32_t DEFAULT_DEVICE_ID = 0;
constexpr int32_t DEFAULT_SENSOR_ID = 0;
constexpr int32_t DEFAULT_LOCATION = 1;
constexpr int32_t GYROSCOPE_SENSOR_ID = 1;
constexpr int32_t AMBIENT_LIGHT_SENSOR_ID = 2;
constexpr int32_t MAGNETIC_FIELD_SENSOR_ID = 3;
constexpr int32_t BAROMETER_SENSOR_ID = 4;
constexpr int32_t HALL_SENSOR_ID = 5;
constexpr int32_t PROXIMITY_SENSOR_ID = 6;
constexpr int32_t ROTATION_VECTOR_SENSOR_ID = 7;
constexpr int32_t GRAVITY_SENSOR_ID = 8;
constexpr int32_t ACCELEROMETER_TYPE = 1;
constexpr int32_t GYROSCOPE_TYPE = 4;
constexpr int32_t AMBIENT_LIGHT_TYPE = 5;
constexpr int32_t MAGNETIC_FIELD_TYPE = 6;
constexpr int32_t BAROMETER_TYPE = 8;
constexpr int32_t HALL_TYPE = 10;
constexpr int32_t PROXIMITY_TYPE = 12;
constexpr int32_t HUMIDITY_TYPE = 14;
constexpr int32_t ROTATION_VECTOR_TYPE = 15;
constexpr int32_t SIGNIFICANT_MOTION_TYPE = 21;
constexpr int32_t PEDOMETER_DETECTION_TYPE = 22;
constexpr int32_t PEDOMETER_TYPE = 23;
constexpr int32_t GRAVITY_TYPE = 256;
constexpr int32_t ACCELEROMETER_UNCALIBRATED_TYPE = 257;
constexpr int32_t MAGNETIC_FIELD_UNCALIBRATED_TYPE = 258;
constexpr int32_t GYROSCOPE_UNCALIBRATED_TYPE = 259;
constexpr int32_t COLOR_TYPE = 278;
constexpr int32_t POSTURE_TYPE = 280;
constexpr int32_t HEADPOSTURE_TYPE = 281;
constexpr int32_t DEFAULT_FIFO_MAX_EVENT_COUNT = 50;
constexpr int32_t OVER_LIMIT_PARAMETER_COUNT = 35;
constexpr int32_t SENSOR_QUEUE_COUNT = 5;
constexpr int64_t MIN_SAMPLE_PERIOD_NS = 10000000;
constexpr int64_t MAX_SAMPLE_PERIOD_NS = 1000000000;
constexpr int64_t ENABLED_SAMPLING_PERIOD_NS = 100000000;
constexpr int64_t TIMESTAMP_STEP_NS = 1000000;
constexpr float TEST_MAX_RANGE = 100.0f;
constexpr size_t COMMON_DIMENSION = 3;
constexpr size_t VECTOR_DIMENSION = 4;
constexpr size_t UNCALIBRATED_DIMENSION = 6;

struct SensorDumpFuzzInput {
    int32_t sensorType = 0;
    int32_t deviceId = 0;
    int32_t sensorId = 0;
    float sensorValue = 0.0f;
};

struct SensorSeed {
    int32_t sensorType;
    int32_t sensorId;
    const char *name;
};

constexpr std::array<SensorSeed, 9> DEFAULT_SENSORS = {{
    { ACCELEROMETER_TYPE, DEFAULT_SENSOR_ID, "Accelerometer" },
    { GYROSCOPE_TYPE, GYROSCOPE_SENSOR_ID, "Gyroscope" },
    { AMBIENT_LIGHT_TYPE, AMBIENT_LIGHT_SENSOR_ID, "AmbientLight" },
    { MAGNETIC_FIELD_TYPE, MAGNETIC_FIELD_SENSOR_ID, "MagneticField" },
    { BAROMETER_TYPE, BAROMETER_SENSOR_ID, "Barometer" },
    { HALL_TYPE, HALL_SENSOR_ID, "Hall" },
    { PROXIMITY_TYPE, PROXIMITY_SENSOR_ID, "Proximity" },
    { ROTATION_VECTOR_TYPE, ROTATION_VECTOR_SENSOR_ID, "RotationVector" },
    { GRAVITY_TYPE, GRAVITY_SENSOR_ID, "Gravity" },
}};

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

void ReadFuzzInput(const uint8_t *data, size_t size, SensorDumpFuzzInput &input)
{
    size_t startPos = 0;
    startPos += GetObject<int32_t>(input.sensorType, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.deviceId, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.sensorId, data + startPos, size - startPos);
    startPos += GetObject<float>(input.sensorValue, data + startPos, size - startPos);
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
        .processName = "SensorDumpFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

Sensor MakeSensor(int32_t sensorTypeId, int32_t deviceId, int32_t sensorId, int32_t location, const std::string &name)
{
    Sensor sensor;
    sensor.SetSensorTypeId(sensorTypeId);
    sensor.SetDeviceId(deviceId);
    sensor.SetSensorId(sensorId);
    sensor.SetLocation(location);
    sensor.SetSensorName(name);
    sensor.SetVendorName("TestVendor");
    sensor.SetMaxRange(TEST_MAX_RANGE);
    sensor.SetFifoMaxEventCount(DEFAULT_FIFO_MAX_EVENT_COUNT);
    sensor.SetMinSamplePeriodNs(MIN_SAMPLE_PERIOD_NS);
    sensor.SetMaxSamplePeriodNs(MAX_SAMPLE_PERIOD_NS);
    sensor.SetIsMockSensor(false);
    return sensor;
}

std::vector<Sensor> BuildSensors(const SensorDumpFuzzInput &input)
{
    std::vector<Sensor> sensors;
    for (const auto &sensorSeed : DEFAULT_SENSORS) {
        sensors.push_back(MakeSensor(sensorSeed.sensorType, DEFAULT_DEVICE_ID,
            sensorSeed.sensorId, DEFAULT_LOCATION, sensorSeed.name));
    }
    sensors.push_back(MakeSensor(input.sensorType, input.deviceId, input.sensorId, DEFAULT_LOCATION, "FuzzSensor"));
    return sensors;
}

void CopyValuesToSensorData(SensorData &sensorData, const float *values, size_t valueCount)
{
    sensorData.dataLen = sizeof(float) * valueCount;
    (void)memcpy_s(sensorData.data, sizeof(sensorData.data), values, sizeof(float) * valueCount);
}

void PrepareClientInfoState(ClientInfo &clientInfo, float sensorValue)
{
    clientInfo.UpdateAppThreadInfo(TEST_PID, TEST_UID, 0);

    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel != nullptr) {
        channel->CreateSensorBasicChannel();
        channel->SetSensorStatus(true);
        clientInfo.UpdateSensorChannel(TEST_PID, channel);
    }

    SensorDescription sensorDesc { DEFAULT_DEVICE_ID, ACCELEROMETER_TYPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION };
    SensorBasicInfo sensorInfo;
    sensorInfo.SetSamplingPeriodNs(ENABLED_SAMPLING_PERIOD_NS);
    sensorInfo.SetMaxReportDelayNs(0);
    sensorInfo.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc, TEST_PID, sensorInfo);

    SensorData sensorData;
    (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
    sensorData.sensorTypeId = ACCELEROMETER_TYPE;
    sensorData.deviceId = DEFAULT_DEVICE_ID;
    sensorData.sensorId = DEFAULT_SENSOR_ID;
    sensorData.location = DEFAULT_LOCATION;
    float values[COMMON_DIMENSION] = { sensorValue, sensorValue + 1.0f, sensorValue + 2.0f };
    CopyValuesToSensorData(sensorData, values, COMMON_DIMENSION);
    for (int32_t index = 0; index < SENSOR_QUEUE_COUNT; ++index) {
        sensorData.timestamp = static_cast<int64_t>(index) * TIMESTAMP_STEP_NS;
        clientInfo.UpdateDataQueue(ACCELEROMETER_TYPE, sensorData);
    }
}

void RunDumpEntryTests(SensorDump &sensorDump, int32_t fd, const std::vector<Sensor> &sensors, ClientInfo &clientInfo)
{
    sensorDump.DumpHelp(fd);
    sensorDump.DumpSensorList(fd, sensors);

    std::vector<Sensor> emptySensors;
    sensorDump.DumpSensorList(fd, emptySensors);
    sensorDump.DumpSensorChannel(fd, clientInfo);
    sensorDump.DumpOpeningSensor(fd, sensors, clientInfo);
}

void RunParseCommandTests(SensorDump &sensorDump, int32_t fd,
    const std::vector<Sensor> &sensors, ClientInfo &clientInfo)
{
    const std::vector<std::vector<std::string>> argumentSets = {
        { "", "-h" },
        { "", "-l" },
        { "", "-c" },
        { "", "-o" },
        { "", "--help" },
        { "", "--list" },
        { "", "--channel" },
        { "", "--open" },
        { "", "-l", "-c", "-o" },
        { "", "-x" },
    };
    for (const auto &args : argumentSets) {
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }

    std::vector<std::string> args = { "" };
    for (int32_t index = 0; index < OVER_LIMIT_PARAMETER_COUNT; ++index) {
        args.push_back("--help");
    }
    sensorDump.ParseCommand(fd, args, sensors, clientInfo);
}

void RunGetDataDimensionTests(SensorDump &sensorDump, int32_t sensorType)
{
    const std::vector<int32_t> sensorTypes = {
        BAROMETER_TYPE,
        HALL_TYPE,
        PROXIMITY_TYPE,
        HUMIDITY_TYPE,
        SIGNIFICANT_MOTION_TYPE,
        PEDOMETER_DETECTION_TYPE,
        PEDOMETER_TYPE,
        COLOR_TYPE,
        ROTATION_VECTOR_TYPE,
        HEADPOSTURE_TYPE,
        MAGNETIC_FIELD_UNCALIBRATED_TYPE,
        GYROSCOPE_UNCALIBRATED_TYPE,
        ACCELEROMETER_UNCALIBRATED_TYPE,
        POSTURE_TYPE,
        ACCELEROMETER_TYPE,
        sensorType,
    };
    for (int32_t currentSensorType : sensorTypes) {
        sensorDump.GetDataDimension(currentSensorType);
    }
}

void RunGetDataBySensorIdTests(SensorDump &sensorDump)
{
    SensorData testData;
    (void)memset_s(&testData, sizeof(testData), 0, sizeof(testData));

    float commonValues[COMMON_DIMENSION] = { 1.0f, 2.0f, 3.0f };
    CopyValuesToSensorData(testData, commonValues, COMMON_DIMENSION);
    sensorDump.GetDataBySensorId(ACCELEROMETER_TYPE, testData);
    sensorDump.GetDataBySensorId(BAROMETER_TYPE, testData);
    sensorDump.GetDataBySensorId(COLOR_TYPE, testData);

    float vectorValues[VECTOR_DIMENSION] = { 1.0f, 2.0f, 3.0f, 4.0f };
    CopyValuesToSensorData(testData, vectorValues, VECTOR_DIMENSION);
    sensorDump.GetDataBySensorId(ROTATION_VECTOR_TYPE, testData);

    float uncalibratedValues[UNCALIBRATED_DIMENSION] = { 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f };
    CopyValuesToSensorData(testData, uncalibratedValues, UNCALIBRATED_DIMENSION);
    sensorDump.GetDataBySensorId(MAGNETIC_FIELD_UNCALIBRATED_TYPE, testData);

    testData.dataLen = 0;
    sensorDump.GetDataBySensorId(ACCELEROMETER_TYPE, testData);
}

void CleanupClientInfoState(ClientInfo &clientInfo)
{
    SensorDescription sensorDesc { DEFAULT_DEVICE_ID, ACCELEROMETER_TYPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION };
    clientInfo.ClearSensorInfo(sensorDesc);
    clientInfo.DestroySensorChannel(TEST_PID);
}
} // namespace

bool SensorDumpFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();

    SensorDumpFuzzInput input;
    ReadFuzzInput(data, size, input);

    int32_t fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        return false;
    }

    SensorDump &sensorDump = SensorDump::GetInstance();
    ClientInfo &clientInfo = ClientInfo::GetInstance();
    std::vector<Sensor> sensors = BuildSensors(input);
    PrepareClientInfoState(clientInfo, input.sensorValue);
    RunDumpEntryTests(sensorDump, fd, sensors, clientInfo);
    RunParseCommandTests(sensorDump, fd, sensors, clientInfo);
    RunGetDataDimensionTests(sensorDump, input.sensorType);
    RunGetDataBySensorIdTests(sensorDump);
    CleanupClientInfoState(clientInfo);
    close(fd);
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
    OHOS::Sensors::SensorDumpFuzzTest(data, size);
    return 0;
}
