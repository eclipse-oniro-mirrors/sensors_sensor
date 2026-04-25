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

#include "geomagneticfield_fuzzer.h"

#include <cmath>
#include <cstddef>
#include <cstdint>

#include "securec.h"

#include "geomagnetic_field.h"

namespace OHOS {
namespace Sensors {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr float MAX_LATITUDE = 90.0f;
constexpr float MAX_LONGITUDE = 180.0f;
constexpr float NEAR_POLE_LATITUDE = 89.99f;
constexpr float OUT_OF_RANGE_LATITUDE = 200.0f;
constexpr float ZERO_ALTITUDE = 0.0f;
constexpr float HIGH_ALTITUDE = 100000.0f;
constexpr float NEGATIVE_ALTITUDE = -1000.0f;
constexpr float DEFAULT_LATITUDE = 30.0f;
constexpr float DEFAULT_LONGITUDE = 120.0f;
constexpr float DEFAULT_ALTITUDE = 500.0f;
constexpr int64_t BASE_TIME_MILLIS = 1580486400000LL;
constexpr int64_t FUTURE_TIME_MILLIS = 1700000000000LL;
constexpr int64_t PAST_TIME_MILLIS = 1000000000000LL;

struct GeomagneticFieldFuzzInput {
    float latitude = 0.0f;
    float longitude = 0.0f;
    float altitude = 0.0f;
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

void ReadFuzzInput(const uint8_t *data, size_t size, GeomagneticFieldFuzzInput &input)
{
    size_t startPos = 0;
    startPos += GetObject<float>(input.latitude, data + startPos, size - startPos);
    startPos += GetObject<float>(input.longitude, data + startPos, size - startPos);
    startPos += GetObject<float>(input.altitude, data + startPos, size - startPos);
    startPos += GetObject<int64_t>(input.timeMillis, data + startPos, size - startPos);
}

void SanitizeInput(GeomagneticFieldFuzzInput &input)
{
    if (std::isnan(input.latitude) || std::isinf(input.latitude)) {
        input.latitude = 0.0f;
    }
    if (std::isnan(input.longitude) || std::isinf(input.longitude)) {
        input.longitude = 0.0f;
    }
    if (std::isnan(input.altitude) || std::isinf(input.altitude)) {
        input.altitude = 0.0f;
    }
}

void RunGeneralAndLatitudeTests(const GeomagneticFieldFuzzInput &input)
{
    GeomagneticField geoField(input.latitude, input.longitude, input.altitude, input.timeMillis);
    geoField.ObtainX();
    geoField.ObtainY();
    geoField.ObtainZ();
    geoField.ObtainGeomagneticDip();
    geoField.ObtainDeflectionAngle();
    geoField.ObtainLevelIntensity();
    geoField.ObtainTotalIntensity();

    GeomagneticField northField(NEAR_POLE_LATITUDE, input.longitude, input.altitude, input.timeMillis);
    northField.ObtainX();
    northField.ObtainY();
    northField.ObtainZ();
    northField.ObtainGeomagneticDip();

    GeomagneticField southField(-NEAR_POLE_LATITUDE, input.longitude, input.altitude, input.timeMillis);
    southField.ObtainX();
    southField.ObtainY();
    southField.ObtainZ();
    southField.ObtainGeomagneticDip();
}

void RunBoundaryAndAltitudeTests(const GeomagneticFieldFuzzInput &input)
{
    GeomagneticField northPole(MAX_LATITUDE, MAX_LONGITUDE, ZERO_ALTITUDE, input.timeMillis);
    northPole.ObtainX();
    northPole.ObtainY();
    northPole.ObtainZ();

    GeomagneticField southPole(-MAX_LATITUDE, -MAX_LONGITUDE, ZERO_ALTITUDE, input.timeMillis);
    southPole.ObtainGeomagneticDip();
    southPole.ObtainDeflectionAngle();
    southPole.ObtainLevelIntensity();
    southPole.ObtainTotalIntensity();

    GeomagneticField highLatitude(OUT_OF_RANGE_LATITUDE, 0.0f, ZERO_ALTITUDE, input.timeMillis);
    highLatitude.ObtainX();
    GeomagneticField lowLatitude(-OUT_OF_RANGE_LATITUDE, 0.0f, ZERO_ALTITUDE, input.timeMillis);
    lowLatitude.ObtainY();

    GeomagneticField zeroAltitude(45.0f, 90.0f, ZERO_ALTITUDE, input.timeMillis);
    zeroAltitude.ObtainZ();
    zeroAltitude.ObtainTotalIntensity();
}

void RunAltitudeTimeAndLongitudeTests(const GeomagneticFieldFuzzInput &input)
{
    GeomagneticField highAltitude(0.0f, 0.0f, HIGH_ALTITUDE, input.timeMillis);
    highAltitude.ObtainX();
    highAltitude.ObtainLevelIntensity();
    GeomagneticField negativeAltitude(0.0f, 0.0f, NEGATIVE_ALTITUDE, input.timeMillis);
    negativeAltitude.ObtainY();
    negativeAltitude.ObtainDeflectionAngle();

    GeomagneticField baseTime(DEFAULT_LATITUDE, DEFAULT_LONGITUDE, DEFAULT_ALTITUDE, BASE_TIME_MILLIS);
    baseTime.ObtainX();
    baseTime.ObtainY();
    baseTime.ObtainZ();
    GeomagneticField futureTime(DEFAULT_LATITUDE, DEFAULT_LONGITUDE, DEFAULT_ALTITUDE, FUTURE_TIME_MILLIS);
    futureTime.ObtainGeomagneticDip();
    GeomagneticField pastTime(DEFAULT_LATITUDE, DEFAULT_LONGITUDE, DEFAULT_ALTITUDE, PAST_TIME_MILLIS);
    pastTime.ObtainDeflectionAngle();
    GeomagneticField zeroTime(DEFAULT_LATITUDE, DEFAULT_LONGITUDE, DEFAULT_ALTITUDE, 0);
    zeroTime.ObtainTotalIntensity();

    GeomagneticField equator(0.0f, 0.0f, ZERO_ALTITUDE, input.timeMillis);
    equator.ObtainX();
    equator.ObtainY();
    equator.ObtainZ();
    equator.ObtainGeomagneticDip();
    equator.ObtainDeflectionAngle();
    equator.ObtainLevelIntensity();
    equator.ObtainTotalIntensity();
    (void)GeomagneticField(45.0f, 45.0f, ZERO_ALTITUDE, input.timeMillis).ObtainX();
    (void)GeomagneticField(45.0f, 90.0f, ZERO_ALTITUDE, input.timeMillis).ObtainX();
    (void)GeomagneticField(45.0f, 135.0f, ZERO_ALTITUDE, input.timeMillis).ObtainX();
    (void)GeomagneticField(45.0f, -90.0f, ZERO_ALTITUDE, input.timeMillis).ObtainX();
}
} // namespace

bool GeomagneticFieldFuzzTest(const uint8_t *data, size_t size)
{
    GeomagneticFieldFuzzInput input;
    ReadFuzzInput(data, size, input);
    SanitizeInput(input);
    RunGeneralAndLatitudeTests(input);
    RunBoundaryAndAltitudeTests(input);
    RunAltitudeTimeAndLongitudeTests(input);
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
    OHOS::Sensors::GeomagneticFieldFuzzTest(data, size);
    return 0;
}
