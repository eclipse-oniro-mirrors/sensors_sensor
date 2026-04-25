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

#include "sensoralgorithm_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "securec.h"

#include "geomagnetic_field.h"
#include "sensor_algorithm.h"

namespace OHOS {
namespace Sensors {
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

bool SensorAlgorithmFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;
    SensorAlgorithm algorithm;

    // Read fuzz floats
    float f1 = 0.0f, f2 = 0.0f, f3 = 0.0f, f4 = 0.0f, f5 = 0.0f, f6 = 0.0f;
    float f7 = 0.0f, f8 = 0.0f, f9 = 0.0f;
    startPos += GetObject<float>(f1, data + startPos, size - startPos);
    startPos += GetObject<float>(f2, data + startPos, size - startPos);
    startPos += GetObject<float>(f3, data + startPos, size - startPos);
    startPos += GetObject<float>(f4, data + startPos, size - startPos);
    startPos += GetObject<float>(f5, data + startPos, size - startPos);
    startPos += GetObject<float>(f6, data + startPos, size - startPos);
    startPos += GetObject<float>(f7, data + startPos, size - startPos);
    startPos += GetObject<float>(f8, data + startPos, size - startPos);
    startPos += GetObject<float>(f9, data + startPos, size - startPos);

    int32_t axisX = 0, axisY = 0;
    startPos += GetObject<int32_t>(axisX, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(axisY, data + startPos, size - startPos);

    int64_t timeMillis = 0;
    startPos += GetObject<int64_t>(timeMillis, data + startPos, size - startPos);

    // ===== 1. CreateQuaternion =====
    // With 3-element rotation vector
    {
        std::vector<float> rotationVector = { f1, f2, f3 };
        std::vector<float> quaternion(4, 0.0f);
        algorithm.CreateQuaternion(rotationVector, quaternion);
    }
    // With 4-element rotation vector
    {
        std::vector<float> rotationVector = { f1, f2, f3, f4 };
        std::vector<float> quaternion(4, 0.0f);
        algorithm.CreateQuaternion(rotationVector, quaternion);
    }
    // Invalid: too short
    {
        std::vector<float> rotationVector = { f1, f2 };
        std::vector<float> quaternion(4, 0.0f);
        algorithm.CreateQuaternion(rotationVector, quaternion);
    }
    // Invalid: quaternion too short
    {
        std::vector<float> rotationVector = { f1, f2, f3 };
        std::vector<float> quaternion(2, 0.0f);
        algorithm.CreateQuaternion(rotationVector, quaternion);
    }

    // ===== 2. CreateRotationMatrix =====
    // 9-element output
    {
        std::vector<float> rotationVector = { f1, f2, f3 };
        std::vector<float> rotationMatrix(9, 0.0f);
        algorithm.CreateRotationMatrix(rotationVector, rotationMatrix);
    }
    // 16-element output
    {
        std::vector<float> rotationVector = { f1, f2, f3 };
        std::vector<float> rotationMatrix(16, 0.0f);
        algorithm.CreateRotationMatrix(rotationVector, rotationMatrix);
    }
    // Invalid size
    {
        std::vector<float> rotationVector = { f1, f2, f3 };
        std::vector<float> rotationMatrix(5, 0.0f);
        algorithm.CreateRotationMatrix(rotationVector, rotationMatrix);
    }

    // ===== 3. TransformCoordinateSystem =====
    // 9-element matrix
    {
        std::vector<float> inMatrix = { f1, f2, f3, f4, f5, f6, f7, f8, f9 };
        std::vector<float> outMatrix(9, 0.0f);
        algorithm.TransformCoordinateSystem(inMatrix, axisX, axisY, outMatrix);
    }
    // 16-element matrix
    {
        std::vector<float> inMatrix(16, 0.0f);
        for (int i = 0; i < 9 && i < 16; i++) {
            inMatrix[i] = f1 + static_cast<float>(i);
        }
        std::vector<float> outMatrix(16, 0.0f);
        algorithm.TransformCoordinateSystem(inMatrix, axisX, axisY, outMatrix);
    }
    // Valid axes: axis values 1,2,3 with optional 0x80 bit
    {
        std::vector<float> inMatrix = { f1, f2, f3, f4, f5, f6, f7, f8, f9 };
        std::vector<float> outMatrix(9, 0.0f);
        algorithm.TransformCoordinateSystem(inMatrix, 1, 2, outMatrix);
        algorithm.TransformCoordinateSystem(inMatrix, 1, 3, outMatrix);
        algorithm.TransformCoordinateSystem(inMatrix, 2, 1, outMatrix);
        algorithm.TransformCoordinateSystem(inMatrix, 2, 3, outMatrix);
        algorithm.TransformCoordinateSystem(inMatrix, 3, 1, outMatrix);
        algorithm.TransformCoordinateSystem(inMatrix, 3, 2, outMatrix);
    }
    // Same in/out matrix (copy path)
    {
        std::vector<float> matrix = { f1, f2, f3, f4, f5, f6, f7, f8, f9 };
        algorithm.TransformCoordinateSystem(matrix, 1, 2, matrix);
    }
    // Invalid: negative axes
    {
        std::vector<float> inMatrix = { f1, f2, f3, f4, f5, f6, f7, f8, f9 };
        std::vector<float> outMatrix(9, 0.0f);
        algorithm.TransformCoordinateSystem(inMatrix, -1, -2, outMatrix);
    }
    // Invalid: wrong matrix size
    {
        std::vector<float> inMatrix = { f1, f2, f3 };
        std::vector<float> outMatrix(3, 0.0f);
        algorithm.TransformCoordinateSystem(inMatrix, 1, 2, outMatrix);
    }
    // Invalid: mismatched sizes
    {
        std::vector<float> inMatrix(9, f1);
        std::vector<float> outMatrix(16, 0.0f);
        algorithm.TransformCoordinateSystem(inMatrix, 1, 2, outMatrix);
    }

    // ===== 4. GetAltitude =====
    {
        float altitude = 0.0f;
        algorithm.GetAltitude(f1, f2, &altitude);
    }
    // seaPressure = 0 (division edge)
    {
        float altitude = 0.0f;
        algorithm.GetAltitude(0.0f, f2, &altitude);
    }
    // null pointer
    {
        algorithm.GetAltitude(f1, f2, nullptr);
    }

    // ===== 5. GetGeomagneticDip =====
    // 9-element
    {
        std::vector<float> inclinationMatrix = { f1, f2, f3, f4, f5, f6, f7, f8, f9 };
        float geomagneticDip = 0.0f;
        algorithm.GetGeomagneticDip(inclinationMatrix, &geomagneticDip);
    }
    // 16-element
    {
        std::vector<float> inclinationMatrix(16, 0.0f);
        for (int i = 0; i < 9; i++) {
            inclinationMatrix[i] = f1 + static_cast<float>(i);
        }
        float geomagneticDip = 0.0f;
        algorithm.GetGeomagneticDip(inclinationMatrix, &geomagneticDip);
    }
    // Invalid size
    {
        std::vector<float> inclinationMatrix = { f1, f2 };
        float geomagneticDip = 0.0f;
        algorithm.GetGeomagneticDip(inclinationMatrix, &geomagneticDip);
    }
    // null pointer
    {
        std::vector<float> inclinationMatrix(9, 0.0f);
        algorithm.GetGeomagneticDip(inclinationMatrix, nullptr);
    }

    // ===== 6. GetAngleModify =====
    // 9x9
    {
        std::vector<float> curMatrix = { f1, f2, f3, f4, f5, f6, f7, f8, f9 };
        std::vector<float> preMatrix = { f9, f8, f7, f6, f5, f4, f3, f2, f1 };
        std::vector<float> angleChange(3, 0.0f);
        algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);
    }
    // 16x16
    {
        std::vector<float> curMatrix(16, f1);
        std::vector<float> preMatrix(16, f2);
        std::vector<float> angleChange(3, 0.0f);
        algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);
    }
    // Mixed 9x16
    {
        std::vector<float> curMatrix(9, f1);
        std::vector<float> preMatrix(16, f2);
        std::vector<float> angleChange(3, 0.0f);
        algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);
    }
    // Invalid: too short output
    {
        std::vector<float> curMatrix(9, f1);
        std::vector<float> preMatrix(9, f2);
        std::vector<float> angleChange(2, 0.0f);
        algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);
    }
    // Invalid: wrong matrix size
    {
        std::vector<float> curMatrix(5, f1);
        std::vector<float> preMatrix(9, f2);
        std::vector<float> angleChange(3, 0.0f);
        algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);
    }

    // ===== 7. GetDirection =====
    // 9-element
    {
        std::vector<float> rotationMatrix = { f1, f2, f3, f4, f5, f6, f7, f8, f9 };
        std::vector<float> rotationAngle(3, 0.0f);
        algorithm.GetDirection(rotationMatrix, rotationAngle);
    }
    // 16-element
    {
        std::vector<float> rotationMatrix(16, f1);
        std::vector<float> rotationAngle(3, 0.0f);
        algorithm.GetDirection(rotationMatrix, rotationAngle);
    }
    // Invalid
    {
        std::vector<float> rotationMatrix(5, f1);
        std::vector<float> rotationAngle(3, 0.0f);
        algorithm.GetDirection(rotationMatrix, rotationAngle);
    }
    {
        std::vector<float> rotationMatrix(9, f1);
        std::vector<float> rotationAngle(2, 0.0f);
        algorithm.GetDirection(rotationMatrix, rotationAngle);
    }

    // ===== 8. CreateRotationAndInclination =====
    {
        std::vector<float> gravity = { 0.0f, 0.0f, 9.81f };
        std::vector<float> geomagnetic = { f1, f2, f3 };
        std::vector<float> rotationMatrix(9, 0.0f);
        std::vector<float> inclinationMatrix(9, 0.0f);
        algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);
    }
    // 16-element outputs
    {
        std::vector<float> gravity = { 0.0f, 0.0f, 9.81f };
        std::vector<float> geomagnetic = { f4, f5, f6 };
        std::vector<float> rotationMatrix(16, 0.0f);
        std::vector<float> inclinationMatrix(16, 0.0f);
        algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);
    }
    // With fuzzed gravity
    {
        std::vector<float> gravity = { f1, f2, f3 };
        std::vector<float> geomagnetic = { f4, f5, f6 };
        std::vector<float> rotationMatrix(9, 0.0f);
        std::vector<float> inclinationMatrix(9, 0.0f);
        algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);
    }
    // Invalid: too short inputs
    {
        std::vector<float> gravity = { f1, f2 };
        std::vector<float> geomagnetic = { f3 };
        std::vector<float> rotationMatrix(9, 0.0f);
        std::vector<float> inclinationMatrix(9, 0.0f);
        algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);
    }
    // Invalid: wrong output sizes
    {
        std::vector<float> gravity = { f1, f2, f3 };
        std::vector<float> geomagnetic = { f4, f5, f6 };
        std::vector<float> rotationMatrix(5, 0.0f);
        std::vector<float> inclinationMatrix(9, 0.0f);
        algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);
    }
    // Zero gravity (should fail totalGravity check)
    {
        std::vector<float> gravity = { 0.0f, 0.0f, 0.0f };
        std::vector<float> geomagnetic = { f4, f5, f6 };
        std::vector<float> rotationMatrix(9, 0.0f);
        std::vector<float> inclinationMatrix(9, 0.0f);
        algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);
    }

    // ===== 9. GeomagneticField =====
    {
        // Clamp values to reasonable ranges to avoid extreme computation
        float latitude = f1;
        float longitude = f2;
        float altitude = f3;
        // Construct the geomagnetic field object
        GeomagneticField geoField(latitude, longitude, altitude, timeMillis);
        geoField.ObtainX();
        geoField.ObtainY();
        geoField.ObtainZ();
        geoField.ObtainGeomagneticDip();
        geoField.ObtainDeflectionAngle();
        geoField.ObtainLevelIntensity();
        geoField.ObtainTotalIntensity();
    }
    // Edge case: extreme latitude/longitude
    {
        GeomagneticField geoField(90.0f, 180.0f, 0.0f, timeMillis);
        geoField.ObtainX();
        geoField.ObtainY();
        geoField.ObtainZ();
    }
    {
        GeomagneticField geoField(-90.0f, -180.0f, 100000.0f, timeMillis);
        geoField.ObtainGeomagneticDip();
        geoField.ObtainDeflectionAngle();
        geoField.ObtainLevelIntensity();
        geoField.ObtainTotalIntensity();
    }

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
    OHOS::Sensors::SensorAlgorithmFuzzTest(data, size);
    return 0;
}
