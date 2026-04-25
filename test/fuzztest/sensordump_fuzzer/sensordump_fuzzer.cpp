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

#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <string>
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
        .processName = "SensorDumpFuzzTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

static Sensor MakeSensor(int32_t sensorTypeId, int32_t deviceId, int32_t sensorId,
    int32_t location, const std::string &name)
{
    Sensor sensor;
    sensor.SetSensorTypeId(sensorTypeId);
    sensor.SetDeviceId(deviceId);
    sensor.SetSensorId(sensorId);
    sensor.SetLocation(location);
    sensor.SetSensorName(name);
    sensor.SetVendorName("TestVendor");
    sensor.SetMaxRange(100.0f);
    sensor.SetFifoMaxEventCount(50);
    sensor.SetMinSamplePeriodNs(10000000);
    sensor.SetMaxSamplePeriodNs(1000000000);
    sensor.SetIsMockSensor(false);
    return sensor;
}

bool SensorDumpFuzzTest(const uint8_t *data, size_t size)
{
    SetUpTestCase();
    size_t startPos = 0;

    int32_t sensorType = 0;
    startPos += GetObject<int32_t>(sensorType, data + startPos, size - startPos);
    int32_t deviceId = 0;
    startPos += GetObject<int32_t>(deviceId, data + startPos, size - startPos);
    int32_t sensorId = 0;
    startPos += GetObject<int32_t>(sensorId, data + startPos, size - startPos);
    float sensorValue = 0.0f;
    startPos += GetObject<float>(sensorValue, data + startPos, size - startPos);

    // Use /dev/null as output fd for dump (safe, won't create files)
    int32_t fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        return false;
    }

    SensorDump &sensorDump = SensorDump::GetInstance();
    ClientInfo &clientInfo = ClientInfo::GetInstance();

    // Prepare sensor list with known sensor types that exist in SensorDump::sensorMap_
    std::vector<Sensor> sensors;
    // SENSOR_TYPE_ID_ACCELEROMETER = 1
    sensors.push_back(MakeSensor(1, 0, 0, 1, "Accelerometer"));
    // SENSOR_TYPE_ID_GYROSCOPE = 4
    sensors.push_back(MakeSensor(4, 0, 1, 1, "Gyroscope"));
    // SENSOR_TYPE_ID_AMBIENT_LIGHT = 5
    sensors.push_back(MakeSensor(5, 0, 2, 1, "AmbientLight"));
    // SENSOR_TYPE_ID_MAGNETIC_FIELD = 6
    sensors.push_back(MakeSensor(6, 0, 3, 1, "MagneticField"));
    // SENSOR_TYPE_ID_BAROMETER = 8
    sensors.push_back(MakeSensor(8, 0, 4, 1, "Barometer"));
    // SENSOR_TYPE_ID_HALL = 10
    sensors.push_back(MakeSensor(10, 0, 5, 1, "Hall"));
    // SENSOR_TYPE_ID_PROXIMITY = 12
    sensors.push_back(MakeSensor(12, 0, 6, 1, "Proximity"));
    // SENSOR_TYPE_ID_ROTATION_VECTOR = 15
    sensors.push_back(MakeSensor(15, 0, 7, 1, "RotationVector"));
    // SENSOR_TYPE_ID_GRAVITY = 256
    sensors.push_back(MakeSensor(256, 0, 8, 1, "Gravity"));
    // Also add fuzzed sensor type (may or may not be in sensorMap_)
    sensors.push_back(MakeSensor(sensorType, deviceId, sensorId, 1, "FuzzSensor"));

    // Set up ClientInfo state so DumpSensorChannel / DumpOpeningSensor have data
    clientInfo.UpdateAppThreadInfo(TEST_PID, TEST_UID, 0);
    sptr<SensorBasicDataChannel> channel = new (std::nothrow) SensorBasicDataChannel();
    if (channel != nullptr) {
        channel->CreateSensorBasicChannel();
        channel->SetSensorStatus(true);
        clientInfo.UpdateSensorChannel(TEST_PID, channel);
    }

    // Enable a sensor so DumpOpeningSensor finds it
    SensorDescription sensorDesc {0, 1, 0, 1};  // Accelerometer
    SensorBasicInfo sensorInfo;
    sensorInfo.SetSamplingPeriodNs(100000000);
    sensorInfo.SetMaxReportDelayNs(0);
    sensorInfo.SetSensorState(true);
    clientInfo.UpdateSensorInfo(sensorDesc, TEST_PID, sensorInfo);

    // Add data to dump queue for DumpSensorData
    SensorData sensorData;
    (void)memset_s(&sensorData, sizeof(sensorData), 0, sizeof(sensorData));
    sensorData.sensorTypeId = 1;  // ACCELEROMETER
    sensorData.deviceId = 0;
    sensorData.sensorId = 0;
    sensorData.location = 1;
    sensorData.dataLen = sizeof(float) * 3;
    float values[3] = { sensorValue, sensorValue + 1.0f, sensorValue + 2.0f };
    (void)memcpy_s(sensorData.data, sizeof(sensorData.data), values, sizeof(values));
    for (int i = 0; i < 5; i++) {
        sensorData.timestamp = i * 1000000;
        clientInfo.UpdateDataQueue(1, sensorData);
    }

    // ===== 1. DumpHelp =====
    sensorDump.DumpHelp(fd);

    // ===== 2. DumpSensorList =====
    sensorDump.DumpSensorList(fd, sensors);
    // Empty sensor list
    {
        std::vector<Sensor> emptySensors;
        sensorDump.DumpSensorList(fd, emptySensors);
    }

    // ===== 3. DumpSensorChannel =====
    sensorDump.DumpSensorChannel(fd, clientInfo);

    // ===== 4. DumpOpeningSensor =====
    sensorDump.DumpOpeningSensor(fd, sensors, clientInfo);

    // ===== 5. ParseCommand with various options =====
    // -h (help)
    {
        std::vector<std::string> args = { "", "-h" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // -l (list)
    {
        std::vector<std::string> args = { "", "-l" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // -c (channel)
    {
        std::vector<std::string> args = { "", "-c" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // -o (opening)
    {
        std::vector<std::string> args = { "", "-o" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // --help
    {
        std::vector<std::string> args = { "", "--help" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // --list
    {
        std::vector<std::string> args = { "", "--list" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // --channel
    {
        std::vector<std::string> args = { "", "--channel" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // --open
    {
        std::vector<std::string> args = { "", "--open" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // Multiple options
    {
        std::vector<std::string> args = { "", "-l", "-c", "-o" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // Unknown option
    {
        std::vector<std::string> args = { "", "-x" };
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }
    // Too many parameters (>32)
    {
        std::vector<std::string> args = { "" };
        for (int i = 0; i < 35; i++) {
            args.push_back("--help");
        }
        sensorDump.ParseCommand(fd, args, sensors, clientInfo);
    }

    // ===== 6. GetDataDimension - test various sensor types =====
    // These are private but accessible via -Dprivate=public
    // BAROMETER (1), HALL (1), PROXIMITY (1), COLOR (2), ROTATION_VECTOR (4),
    // MAGNETIC_FIELD_UNCALIBRATED (6), POSTURE (7), default (3)
    sensorDump.GetDataDimension(8);   // BAROMETER -> SOLITARIES_DIMENSION
    sensorDump.GetDataDimension(10);  // HALL -> SOLITARIES_DIMENSION
    sensorDump.GetDataDimension(12);  // PROXIMITY -> SOLITARIES_DIMENSION
    sensorDump.GetDataDimension(14);  // HUMIDITY -> SOLITARIES_DIMENSION
    sensorDump.GetDataDimension(21);  // SIGNIFICANT_MOTION -> SOLITARIES_DIMENSION
    sensorDump.GetDataDimension(22);  // PEDOMETER_DETECTION -> SOLITARIES_DIMENSION
    sensorDump.GetDataDimension(23);  // PEDOMETER -> SOLITARIES_DIMENSION
    sensorDump.GetDataDimension(278); // COLOR -> TWO_DIMENSION
    sensorDump.GetDataDimension(15);  // ROTATION_VECTOR -> VECTOR_DIMENSION
    sensorDump.GetDataDimension(281); // HEADPOSTURE -> VECTOR_DIMENSION
    sensorDump.GetDataDimension(258); // MAGNETIC_FIELD_UNCALIBRATED -> UNCALIBRATED_DIMENSION
    sensorDump.GetDataDimension(259); // GYROSCOPE_UNCALIBRATED -> UNCALIBRATED_DIMENSION
    sensorDump.GetDataDimension(257); // ACCELEROMETER_UNCALIBRATED -> UNCALIBRATED_DIMENSION
    sensorDump.GetDataDimension(280); // POSTURE -> SEVEN_DIMENSION
    sensorDump.GetDataDimension(1);   // ACCELEROMETER -> default COMMON_DIMENSION
    sensorDump.GetDataDimension(sensorType); // fuzzed type

    // ===== 7. GetDataBySensorId =====
    {
        SensorData testData;
        (void)memset_s(&testData, sizeof(testData), 0, sizeof(testData));
        testData.dataLen = sizeof(float) * 3;
        float vals[3] = { 1.0f, 2.0f, 3.0f };
        (void)memcpy_s(testData.data, sizeof(testData.data), vals, sizeof(vals));
        // Accelerometer (default dimension = 3)
        sensorDump.GetDataBySensorId(1, testData);
        // Barometer (dimension = 1)
        sensorDump.GetDataBySensorId(8, testData);
        // Color (dimension = 2)
        sensorDump.GetDataBySensorId(278, testData);
        // Rotation vector (dimension = 4)
        testData.dataLen = sizeof(float) * 4;
        float vals4[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
        (void)memcpy_s(testData.data, sizeof(testData.data), vals4, sizeof(vals4));
        sensorDump.GetDataBySensorId(15, testData);
        // Uncalibrated (dimension = 6)
        testData.dataLen = sizeof(float) * 6;
        float vals6[6] = { 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f };
        (void)memcpy_s(testData.data, sizeof(testData.data), vals6, sizeof(vals6));
        sensorDump.GetDataBySensorId(258, testData);
        // dataLen too small
        testData.dataLen = 0;
        sensorDump.GetDataBySensorId(1, testData);
    }

    // Cleanup
    clientInfo.ClearSensorInfo(sensorDesc);
    clientInfo.DestroySensorChannel(TEST_PID);
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
