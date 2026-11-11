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

#include <atomic>
#include <gtest/gtest.h>

#include "async_callback_info.h"

#undef LOG_TAG
#define LOG_TAG "AsyncCallbackInfoTest"

namespace {
std::atomic<int32_t> g_napiCallCount(0);
} // namespace

// async_callback_info.h only ever calls these three napi entry points, and the
// env-invalid guard under test must prevent exactly these calls on a dead env.
// The stubs keep the test hermetic: no JS engine is linked, and the fake env
// pointer never reaches a real implementation. The linkage of each stub follows
// its declaration: napi_delete_reference is declared inside extern "C" in
// js_native_api.h, the other two are C++ declarations.
napi_status napi_send_event(napi_env env, const std::function<void()> &cb, napi_event_priority priority,
    const char *name, napi_event_barrier_option option)
{
    g_napiCallCount.fetch_add(1);
    return napi_ok;
}

napi_status napi_delete_async_work(napi_env env, napi_async_work work)
{
    g_napiCallCount.fetch_add(1);
    return napi_ok;
}

extern "C" napi_status napi_delete_reference(napi_env env, napi_ref ref)
{
    g_napiCallCount.fetch_add(1);
    return napi_ok;
}

namespace OHOS {
namespace Sensors {
using namespace testing::ext;
namespace {

napi_env FakeEnv()
{
    return reinterpret_cast<napi_env>(0x1234);
}
} // namespace

class AsyncCallbackInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() override
    {
        g_napiCallCount.store(0);
    }

    void TearDown() override {}
};

/**
 * @tc.name: AsyncCallbackInfoDestructor_001
 * @tc.desc: ONCE_CALLBACK returns before any napi access even with a live-looking env
 * @tc.type: FUNC
 */
HWTEST_F(AsyncCallbackInfoTest, AsyncCallbackInfoDestructor_001, TestSize.Level1)
{
    {
        AsyncCallbackInfo info(FakeEnv(), ONCE_CALLBACK);
        info.asyncWork = reinterpret_cast<napi_async_work>(0x5678);
        info.callback[0] = reinterpret_cast<napi_ref>(0x9abc);
    }
    EXPECT_EQ(g_napiCallCount.load(), 0);
}

/**
 * @tc.name: AsyncCallbackInfoDestructor_002
 * @tc.desc: The env-invalid flag makes the destructor skip every napi call on a dead env
 * @tc.type: FUNC
 */
HWTEST_F(AsyncCallbackInfoTest, AsyncCallbackInfoDestructor_002, TestSize.Level1)
{
    {
        AsyncCallbackInfo info(FakeEnv(), ON_CALLBACK);
        info.isEnvInvalid_.store(true);
        info.asyncWork = reinterpret_cast<napi_async_work>(0x5678);
        info.callback[0] = reinterpret_cast<napi_ref>(0x9abc);
    }
    EXPECT_EQ(g_napiCallCount.load(), 0);
}

/**
 * @tc.name: AsyncCallbackInfoDestructor_003
 * @tc.desc: The env-invalid guard also covers the subscribe callback type with null members
 * @tc.type: FUNC
 */
HWTEST_F(AsyncCallbackInfoTest, AsyncCallbackInfoDestructor_003, TestSize.Level1)
{
    {
        AsyncCallbackInfo info(FakeEnv(), SUBSCRIBE_CALLBACK);
        info.isEnvInvalid_.store(true);
    }
    EXPECT_EQ(g_napiCallCount.load(), 0);
}

/**
 * @tc.name: AsyncCallbackInfoDestructor_004
 * @tc.desc: Without the flag, null async work and null references are skipped by the
 *           per-member null checks without touching napi
 * @tc.type: FUNC
 */
HWTEST_F(AsyncCallbackInfoTest, AsyncCallbackInfoDestructor_004, TestSize.Level1)
{
    {
        AsyncCallbackInfo info(FakeEnv(), GET_SENSOR_LIST);
    }
    EXPECT_EQ(g_napiCallCount.load(), 0);
}

/**
 * @tc.name: AsyncCallbackInfoDestructor_005
 * @tc.desc: Positive control: without the flag and with live-looking members the
 *           destructor queues exactly one deletion event per resource (one async
 *           work plus three references), proving the stubs and the counter work
 * @tc.type: FUNC
 */
HWTEST_F(AsyncCallbackInfoTest, AsyncCallbackInfoDestructor_005, TestSize.Level1)
{
    {
        AsyncCallbackInfo info(FakeEnv(), GET_SENSOR_LIST);
        info.asyncWork = reinterpret_cast<napi_async_work>(0x5678);
        info.callback[0] = reinterpret_cast<napi_ref>(0x9abc);
        info.callback[1] = reinterpret_cast<napi_ref>(0x9abd);
        info.callback[2] = reinterpret_cast<napi_ref>(0x9abe);
    }
    EXPECT_EQ(g_napiCallCount.load(), 4); // 1 async work + 3 references
}
} // namespace Sensors
} // namespace OHOS
