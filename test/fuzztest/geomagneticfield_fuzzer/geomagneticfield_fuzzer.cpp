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

#include <cstddef>
#include <cstdint>
#include <cmath>

#include "securec.h"

#include "geomagnetic_field.h"

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

bool GeomagneticFieldFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;

    float latitude = 0.0f;
    startPos += GetObject<float>(latitude, data + startPos, size - startPos);
    float longitude = 0.0f;
    startPos += GetObject<float>(longitude, data + startPos, size - startPos);
    float altitude = 0.0f;
    startPos += GetObject<float>(altitude, data + startPos, size - startPos);
    int64_t timeMillis = 0;
    startPos += GetObject<int64_t>(timeMillis, data + startPos, size - startPos);

    // Filter out NaN/Inf to avoid infinite loops in trig functions
    if (std::isnan(latitude) || std::isinf(latitude)) {
        latitude = 0.0f;
    }
    if (std::isnan(longitude) || std::isinf(longitude)) {
        longitude = 0.0f;
    }
    if (std::isnan(altitude) || std::isinf(altitude)) {
        altitude = 0.0f;
    }

    // ===== 1. Fuzzed input - exercises constructor, CalibrateGeocentricCoordinates,
    //          InitLegendreTable, GetRelativeRadiusPower, GetLongitudeTrigonometric,
    //          CalculateGeomagneticComponent =====
    {
        GeomagneticField geoField(latitude, longitude, altitude, timeMillis);
        geoField.ObtainX();
        geoField.ObtainY();
        geoField.ObtainZ();
        geoField.ObtainGeomagneticDip();
        geoField.ObtainDeflectionAngle();
        geoField.ObtainLevelIntensity();
        geoField.ObtainTotalIntensity();
    }

    // ===== 2. Boundary: max latitude (near 90) =====
    {
        GeomagneticField geoField(89.99f, longitude, altitude, timeMillis);
        geoField.ObtainX();
        geoField.ObtainY();
        geoField.ObtainZ();
        geoField.ObtainGeomagneticDip();
        geoField.ObtainDeflectionAngle();
        geoField.ObtainLevelIntensity();
        geoField.ObtainTotalIntensity();
    }

    // ===== 3. Boundary: min latitude (near -90) =====
    {
        GeomagneticField geoField(-89.99f, longitude, altitude, timeMillis);
        geoField.ObtainX();
        geoField.ObtainY();
        geoField.ObtainZ();
        geoField.ObtainGeomagneticDip();
        geoField.ObtainDeflectionAngle();
        geoField.ObtainLevelIntensity();
        geoField.ObtainTotalIntensity();
    }

    // ===== 4. Boundary: exact 90/-90 (precision clamp path) =====
    {
        GeomagneticField geoField(90.0f, 180.0f, 0.0f, timeMillis);
        geoField.ObtainX();
        geoField.ObtainY();
        geoField.ObtainZ();
    }
    {
        GeomagneticField geoField(-90.0f, -180.0f, 0.0f, timeMillis);
        geoField.ObtainGeomagneticDip();
        geoField.ObtainDeflectionAngle();
        geoField.ObtainLevelIntensity();
        geoField.ObtainTotalIntensity();
    }

    // ===== 5. Beyond latitude bounds (clamp to ±90-precision) =====
    {
        GeomagneticField geoField(200.0f, 0.0f, 0.0f, timeMillis);
        geoField.ObtainX();
    }
    {
        GeomagneticField geoField(-200.0f, 0.0f, 0.0f, timeMillis);
        geoField.ObtainY();
    }

    // ===== 6. Zero altitude =====
    {
        GeomagneticField geoField(45.0f, 90.0f, 0.0f, timeMillis);
        geoField.ObtainZ();
        geoField.ObtainTotalIntensity();
    }

    // ===== 7. Very high altitude =====
    {
        GeomagneticField geoField(0.0f, 0.0f, 100000.0f, timeMillis);
        geoField.ObtainX();
        geoField.ObtainLevelIntensity();
    }

    // ===== 8. Negative altitude =====
    {
        GeomagneticField geoField(0.0f, 0.0f, -1000.0f, timeMillis);
        geoField.ObtainY();
        geoField.ObtainDeflectionAngle();
    }

    // ===== 9. Different timeMillis values =====
    {
        // Base WMM time
        GeomagneticField geoField(30.0f, 120.0f, 500.0f, 1580486400000LL);
        geoField.ObtainX();
        geoField.ObtainY();
        geoField.ObtainZ();
    }
    {
        // Future time
        GeomagneticField geoField(30.0f, 120.0f, 500.0f, 1700000000000LL);
        geoField.ObtainGeomagneticDip();
    }
    {
        // Past time (negative yearsSinceBase)
        GeomagneticField geoField(30.0f, 120.0f, 500.0f, 1000000000000LL);
        geoField.ObtainDeflectionAngle();
    }
    {
        // Zero time
        GeomagneticField geoField(30.0f, 120.0f, 500.0f, 0);
        geoField.ObtainTotalIntensity();
    }

    // ===== 10. Equator and prime meridian =====
    {
        GeomagneticField geoField(0.0f, 0.0f, 0.0f, timeMillis);
        geoField.ObtainX();
        geoField.ObtainY();
        geoField.ObtainZ();
        geoField.ObtainGeomagneticDip();
        geoField.ObtainDeflectionAngle();
        geoField.ObtainLevelIntensity();
        geoField.ObtainTotalIntensity();
    }

    // ===== 11. Various longitude values to exercise GetLongitudeTrigonometric =====
    {
        GeomagneticField geoField(45.0f, 0.0f, 0.0f, timeMillis);
        geoField.ObtainX();
    }
    {
        GeomagneticField geoField(45.0f, 45.0f, 0.0f, timeMillis);
        geoField.ObtainX();
    }
    {
        GeomagneticField geoField(45.0f, 90.0f, 0.0f, timeMillis);
        geoField.ObtainX();
    }
    {
        GeomagneticField geoField(45.0f, 135.0f, 0.0f, timeMillis);
        geoField.ObtainX();
    }
    {
        GeomagneticField geoField(45.0f, -90.0f, 0.0f, timeMillis);
        geoField.ObtainX();
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
    OHOS::Sensors::GeomagneticFieldFuzzTest(data, size);
    return 0;
}
