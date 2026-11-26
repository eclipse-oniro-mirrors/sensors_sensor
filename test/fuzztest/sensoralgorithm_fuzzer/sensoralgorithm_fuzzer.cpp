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

#include "sensoralgorithm_fuzzer.h"

#include <array>
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
constexpr size_t VECTOR_SIZE_TWO = 2;
constexpr size_t VECTOR_SIZE_THREE = 3;
constexpr size_t VECTOR_SIZE_FOUR = 4;
constexpr size_t MATRIX_SIZE_NINE = 9;
constexpr size_t MATRIX_SIZE_SIXTEEN = 16;
constexpr size_t INVALID_MATRIX_SIZE = 5;
constexpr size_t VALUE_INDEX_ZERO = 0;
constexpr size_t VALUE_INDEX_ONE = 1;
constexpr size_t VALUE_INDEX_TWO = 2;
constexpr size_t VALUE_INDEX_THREE = 3;
constexpr size_t VALUE_INDEX_FOUR = 4;
constexpr size_t VALUE_INDEX_FIVE = 5;
constexpr int32_t AXIS_X = 1;
constexpr int32_t AXIS_Y = 2;
constexpr int32_t AXIS_Z = 3;
constexpr float STANDARD_GRAVITY = 9.81f;
constexpr float MAX_LATITUDE = 90.0f;
constexpr float MAX_LONGITUDE = 180.0f;
constexpr float HIGH_ALTITUDE = 100000.0f;

struct SensorAlgorithmFuzzInput {
    std::array<float, MATRIX_SIZE_NINE> values {};
    int32_t axisX = 0;
    int32_t axisY = 0;
    int64_t timeMillis = 0;
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

void ReadFuzzInput(const uint8_t *data, size_t size, SensorAlgorithmFuzzInput &input)
{
    size_t startPos = 0;
    for (size_t index = 0; index < input.values.size(); ++index) {
        startPos += GetObject<float>(input.values[index], data + startPos, size - startPos);
    }
    startPos += GetObject<int32_t>(input.axisX, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(input.axisY, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.timeMillis, data + startPos, size - startPos);
}

std::vector<float> MakeValues(const SensorAlgorithmFuzzInput &input, size_t count)
{
    return std::vector<float>(input.values.begin(), input.values.begin() + count);
}

std::vector<float> MakeReverseMatrix(const SensorAlgorithmFuzzInput &input)
{
    return std::vector<float>(input.values.rbegin(), input.values.rend());
}

void FillSixteenElementMatrix(std::vector<float> &matrix, float baseValue)
{
    for (size_t index = 0; index < MATRIX_SIZE_NINE; ++index) {
        matrix[index] = baseValue + static_cast<float>(index);
    }
}

void TestCreateQuaternion(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> rotationVector = MakeValues(input, VECTOR_SIZE_THREE);
    std::vector<float> quaternion(VECTOR_SIZE_FOUR, 0.0f);
    algorithm.CreateQuaternion(rotationVector, quaternion);

    rotationVector = MakeValues(input, VECTOR_SIZE_FOUR);
    algorithm.CreateQuaternion(rotationVector, quaternion);

    rotationVector = MakeValues(input, VECTOR_SIZE_TWO);
    algorithm.CreateQuaternion(rotationVector, quaternion);

    rotationVector = MakeValues(input, VECTOR_SIZE_THREE);
    quaternion.assign(VECTOR_SIZE_TWO, 0.0f);
    algorithm.CreateQuaternion(rotationVector, quaternion);
}

void TestCreateRotationMatrix(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> rotationVector = MakeValues(input, VECTOR_SIZE_THREE);
    std::vector<float> rotationMatrix(MATRIX_SIZE_NINE, 0.0f);
    algorithm.CreateRotationMatrix(rotationVector, rotationMatrix);

    rotationMatrix.assign(MATRIX_SIZE_SIXTEEN, 0.0f);
    algorithm.CreateRotationMatrix(rotationVector, rotationMatrix);

    rotationMatrix.assign(INVALID_MATRIX_SIZE, 0.0f);
    algorithm.CreateRotationMatrix(rotationVector, rotationMatrix);
}

void TestTransformCoordinateSystemCommon(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> inMatrix = MakeValues(input, MATRIX_SIZE_NINE);
    std::vector<float> outMatrix(MATRIX_SIZE_NINE, 0.0f);
    algorithm.TransformCoordinateSystem(inMatrix, input.axisX, input.axisY, outMatrix);

    inMatrix.assign(MATRIX_SIZE_SIXTEEN, 0.0f);
    FillSixteenElementMatrix(inMatrix, input.values[VALUE_INDEX_ZERO]);
    outMatrix.assign(MATRIX_SIZE_SIXTEEN, 0.0f);
    algorithm.TransformCoordinateSystem(inMatrix, input.axisX, input.axisY, outMatrix);

    inMatrix = MakeValues(input, MATRIX_SIZE_NINE);
    outMatrix.assign(MATRIX_SIZE_NINE, 0.0f);
    algorithm.TransformCoordinateSystem(inMatrix, AXIS_X, AXIS_Y, outMatrix);
    algorithm.TransformCoordinateSystem(inMatrix, AXIS_X, AXIS_Z, outMatrix);
    algorithm.TransformCoordinateSystem(inMatrix, AXIS_Y, AXIS_X, outMatrix);
    algorithm.TransformCoordinateSystem(inMatrix, AXIS_Y, AXIS_Z, outMatrix);
    algorithm.TransformCoordinateSystem(inMatrix, AXIS_Z, AXIS_X, outMatrix);
    algorithm.TransformCoordinateSystem(inMatrix, AXIS_Z, AXIS_Y, outMatrix);
}

void TestTransformCoordinateSystemEdge(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> matrix = MakeValues(input, MATRIX_SIZE_NINE);
    algorithm.TransformCoordinateSystem(matrix, AXIS_X, AXIS_Y, matrix);

    std::vector<float> inMatrix = MakeValues(input, MATRIX_SIZE_NINE);
    std::vector<float> outMatrix(MATRIX_SIZE_NINE, 0.0f);
    algorithm.TransformCoordinateSystem(inMatrix, -AXIS_X, -AXIS_Y, outMatrix);

    inMatrix = MakeValues(input, VECTOR_SIZE_THREE);
    outMatrix.assign(VECTOR_SIZE_THREE, 0.0f);
    algorithm.TransformCoordinateSystem(inMatrix, AXIS_X, AXIS_Y, outMatrix);

    inMatrix.assign(MATRIX_SIZE_NINE, input.values[VALUE_INDEX_ZERO]);
    outMatrix.assign(MATRIX_SIZE_SIXTEEN, 0.0f);
    algorithm.TransformCoordinateSystem(inMatrix, AXIS_X, AXIS_Y, outMatrix);
}

void TestGetAltitude(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    float altitude = 0.0f;
    algorithm.GetAltitude(input.values[VALUE_INDEX_ZERO], input.values[VALUE_INDEX_ONE], &altitude);
    algorithm.GetAltitude(0.0f, input.values[VALUE_INDEX_ONE], &altitude);
    algorithm.GetAltitude(input.values[VALUE_INDEX_ZERO], input.values[VALUE_INDEX_ONE], nullptr);
}

void TestGetGeomagneticDip(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> inclinationMatrix = MakeValues(input, MATRIX_SIZE_NINE);
    float geomagneticDip = 0.0f;
    algorithm.GetGeomagneticDip(inclinationMatrix, &geomagneticDip);

    inclinationMatrix.assign(MATRIX_SIZE_SIXTEEN, 0.0f);
    FillSixteenElementMatrix(inclinationMatrix, input.values[VALUE_INDEX_ZERO]);
    algorithm.GetGeomagneticDip(inclinationMatrix, &geomagneticDip);

    inclinationMatrix = MakeValues(input, VECTOR_SIZE_TWO);
    algorithm.GetGeomagneticDip(inclinationMatrix, &geomagneticDip);

    inclinationMatrix.assign(MATRIX_SIZE_NINE, 0.0f);
    algorithm.GetGeomagneticDip(inclinationMatrix, nullptr);
}

void TestGetAngleModifyCommon(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> curMatrix = MakeValues(input, MATRIX_SIZE_NINE);
    std::vector<float> preMatrix = MakeReverseMatrix(input);
    std::vector<float> angleChange(VECTOR_SIZE_THREE, 0.0f);
    algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);

    curMatrix.assign(MATRIX_SIZE_SIXTEEN, input.values[VALUE_INDEX_ZERO]);
    preMatrix.assign(MATRIX_SIZE_SIXTEEN, input.values[VALUE_INDEX_ONE]);
    algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);

    curMatrix.assign(MATRIX_SIZE_NINE, input.values[VALUE_INDEX_ZERO]);
    preMatrix.assign(MATRIX_SIZE_SIXTEEN, input.values[VALUE_INDEX_ONE]);
    algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);
}

void TestGetAngleModifyEdge(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> curMatrix(MATRIX_SIZE_NINE, input.values[VALUE_INDEX_ZERO]);
    std::vector<float> preMatrix(MATRIX_SIZE_NINE, input.values[VALUE_INDEX_ONE]);
    std::vector<float> angleChange(VECTOR_SIZE_TWO, 0.0f);
    algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);

    curMatrix.assign(INVALID_MATRIX_SIZE, input.values[VALUE_INDEX_ZERO]);
    preMatrix.assign(MATRIX_SIZE_NINE, input.values[VALUE_INDEX_ONE]);
    angleChange.assign(VECTOR_SIZE_THREE, 0.0f);
    algorithm.GetAngleModify(curMatrix, preMatrix, angleChange);
}

void TestGetDirection(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> rotationMatrix = MakeValues(input, MATRIX_SIZE_NINE);
    std::vector<float> rotationAngle(VECTOR_SIZE_THREE, 0.0f);
    algorithm.GetDirection(rotationMatrix, rotationAngle);

    rotationMatrix.assign(MATRIX_SIZE_SIXTEEN, input.values[VALUE_INDEX_ZERO]);
    algorithm.GetDirection(rotationMatrix, rotationAngle);

    rotationMatrix.assign(INVALID_MATRIX_SIZE, input.values[VALUE_INDEX_ZERO]);
    algorithm.GetDirection(rotationMatrix, rotationAngle);

    rotationMatrix.assign(MATRIX_SIZE_NINE, input.values[VALUE_INDEX_ZERO]);
    rotationAngle.assign(VECTOR_SIZE_TWO, 0.0f);
    algorithm.GetDirection(rotationMatrix, rotationAngle);
}

void TestCreateRotationAndInclinationCommon(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> gravity = { 0.0f, 0.0f, STANDARD_GRAVITY };
    std::vector<float> geomagnetic = MakeValues(input, VECTOR_SIZE_THREE);
    std::vector<float> rotationMatrix(MATRIX_SIZE_NINE, 0.0f);
    std::vector<float> inclinationMatrix(MATRIX_SIZE_NINE, 0.0f);
    algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);

    geomagnetic = { input.values[VALUE_INDEX_THREE], input.values[VALUE_INDEX_FOUR], input.values[VALUE_INDEX_FIVE] };
    rotationMatrix.assign(MATRIX_SIZE_SIXTEEN, 0.0f);
    inclinationMatrix.assign(MATRIX_SIZE_SIXTEEN, 0.0f);
    algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);

    gravity = MakeValues(input, VECTOR_SIZE_THREE);
    rotationMatrix.assign(MATRIX_SIZE_NINE, 0.0f);
    inclinationMatrix.assign(MATRIX_SIZE_NINE, 0.0f);
    algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);
}

void TestCreateRotationAndInclinationEdge(SensorAlgorithm &algorithm, const SensorAlgorithmFuzzInput &input)
{
    std::vector<float> gravity = MakeValues(input, VECTOR_SIZE_TWO);
    std::vector<float> geomagnetic = { input.values[VALUE_INDEX_TWO] };
    std::vector<float> rotationMatrix(MATRIX_SIZE_NINE, 0.0f);
    std::vector<float> inclinationMatrix(MATRIX_SIZE_NINE, 0.0f);
    algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);

    gravity = MakeValues(input, VECTOR_SIZE_THREE);
    geomagnetic = { input.values[VALUE_INDEX_THREE], input.values[VALUE_INDEX_FOUR], input.values[VALUE_INDEX_FIVE] };
    rotationMatrix.assign(INVALID_MATRIX_SIZE, 0.0f);
    algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);

    gravity = { 0.0f, 0.0f, 0.0f };
    rotationMatrix.assign(MATRIX_SIZE_NINE, 0.0f);
    inclinationMatrix.assign(MATRIX_SIZE_NINE, 0.0f);
    algorithm.CreateRotationAndInclination(gravity, geomagnetic, rotationMatrix, inclinationMatrix);
}

void TestGeomagneticFieldCommon(const SensorAlgorithmFuzzInput &input)
{
    GeomagneticField geoField(input.values[VALUE_INDEX_ZERO], input.values[VALUE_INDEX_ONE],
        input.values[VALUE_INDEX_TWO], input.timeMillis);
    geoField.ObtainX();
    geoField.ObtainY();
    geoField.ObtainZ();
    geoField.ObtainGeomagneticDip();
    geoField.ObtainDeflectionAngle();
    geoField.ObtainLevelIntensity();
    geoField.ObtainTotalIntensity();
}

void TestGeomagneticFieldEdge(const SensorAlgorithmFuzzInput &input)
{
    GeomagneticField northPole(MAX_LATITUDE, MAX_LONGITUDE, 0.0f, input.timeMillis);
    northPole.ObtainX();
    northPole.ObtainY();
    northPole.ObtainZ();

    GeomagneticField southPole(-MAX_LATITUDE, -MAX_LONGITUDE, HIGH_ALTITUDE, input.timeMillis);
    southPole.ObtainGeomagneticDip();
    southPole.ObtainDeflectionAngle();
    southPole.ObtainLevelIntensity();
    southPole.ObtainTotalIntensity();
}
} // namespace

bool SensorAlgorithmFuzzTest(const uint8_t *data, size_t size)
{
    SensorAlgorithmFuzzInput input;
    ReadFuzzInput(data, size, input);

    SensorAlgorithm algorithm;
    TestCreateQuaternion(algorithm, input);
    TestCreateRotationMatrix(algorithm, input);
    TestTransformCoordinateSystemCommon(algorithm, input);
    TestTransformCoordinateSystemEdge(algorithm, input);
    TestGetAltitude(algorithm, input);
    TestGetGeomagneticDip(algorithm, input);
    TestGetAngleModifyCommon(algorithm, input);
    TestGetAngleModifyEdge(algorithm, input);
    TestGetDirection(algorithm, input);
    TestCreateRotationAndInclinationCommon(algorithm, input);
    TestCreateRotationAndInclinationEdge(algorithm, input);
    TestGeomagneticFieldCommon(input);
    TestGeomagneticFieldEdge(input);
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
