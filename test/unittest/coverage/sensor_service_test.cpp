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

#include <algorithm>

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "ipc_object_stub.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "client_info.h"
#include "sensor_agent_type.h"
#include "sensor_data_block_policy.h"
#include "sensor_service.h"

#undef LOG_TAG
#define LOG_TAG "SensorServiceTest"

namespace OHOS {
namespace Sensors {
using namespace testing::ext;
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

namespace {
constexpr int32_t TEST_INVALID_PID = -1;
constexpr int32_t TEST_PID = 4321;
constexpr int32_t TEST_PID_OTHER = 8765;
constexpr int32_t TEST_TARGET_PID = 9999;
constexpr int32_t TEST_SENSOR_TYPE = SENSOR_TYPE_ID_ACCELEROMETER;
} // namespace

class SensorServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SensorServiceTest::SetUpTestCase()
{
    // A native token is required by the IsNativeToken gate in DestroySocketChannel.
    const char **perms = new (std::nothrow) const char *[1];
    if (perms == nullptr) {
        return;
    }
    perms[0] = "ohos.permission.MANAGE_SENSOR";
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "SensorServiceTest",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

void SensorServiceTest::TearDownTestCase() {}

void SensorServiceTest::SetUp()
{
    SensorDataBlockPolicy::GetInstance().ClearAllBlockPolicies();
}

void SensorServiceTest::TearDown()
{
    SensorDataBlockPolicy::GetInstance().ClearAllBlockPolicies();
}

namespace {
SensorService *GetService()
{
    return SensorDelayedSpSingleton<SensorService>::GetInstance().GetRefPtr();
}

bool InSensorClients(SensorService *service, const sptr<IRemoteObject> &client)
{
    auto &clients = service->clientInfo_.sensorClients_;
    return std::find(clients.begin(), clients.end(), client) != clients.end();
}

void SetBlockPolicyIssuedByTestPid()
{
    std::vector<int32_t> sensorTypes = { TEST_SENSOR_TYPE };
    ErrCode ret = SensorDataBlockPolicy::GetInstance().BlockSensorDataByPid(TEST_TARGET_PID, sensorTypes, TEST_PID);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_TRUE(SensorDataBlockPolicy::GetInstance().IsSensorDataBlocked(TEST_TARGET_PID, TEST_SENSOR_TYPE));
}
} // namespace

/**
 * @tc.name: SensorServiceTest_TransferClientRemoteObject_001
 * @tc.desc: Transfer a null remote object; nothing is registered and no crash happens
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_TransferClientRemoteObject_001, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> nullClient = nullptr;
    EXPECT_EQ(service->TransferClientRemoteObject(nullClient), ERR_OK);
}

/**
 * @tc.name: SensorServiceTest_TransferClientRemoteObject_002
 * @tc.desc: Transferring a client registers the death recipient before saving the client,
 *           so both the pid mapping and the broadcast list membership exist afterwards
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_TransferClientRemoteObject_002, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> client = new (std::nothrow) IPCObjectStub();
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(service->TransferClientRemoteObject(client), ERR_OK);
    EXPECT_EQ(service->clientInfo_.FindClientPid(client), IPCSkeleton::GetCallingPid());
    EXPECT_TRUE(InSensorClients(service, client));
}

/**
 * @tc.name: SensorServiceTest_RegisterClientDeathRecipient_001
 * @tc.desc: A null client is rejected by the null check without any state change
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_RegisterClientDeathRecipient_001, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> nullClient = nullptr;
    service->RegisterClientDeathRecipient(nullClient, TEST_PID); // must not crash
}

/**
 * @tc.name: SensorServiceTest_RegisterClientDeathRecipient_002
 * @tc.desc: Registering a fresh client creates the pid mapping
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_RegisterClientDeathRecipient_002, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> client = new (std::nothrow) IPCObjectStub();
    ASSERT_NE(client, nullptr);
    service->RegisterClientDeathRecipient(client, TEST_PID);
    EXPECT_EQ(service->clientInfo_.FindClientPid(client), TEST_PID);
}

/**
 * @tc.name: SensorServiceTest_RegisterClientDeathRecipient_003
 * @tc.desc: Registering an already registered client is idempotent: the early return
 *           keeps the original pid instead of updating the mapping
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_RegisterClientDeathRecipient_003, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> client = new (std::nothrow) IPCObjectStub();
    ASSERT_NE(client, nullptr);
    service->RegisterClientDeathRecipient(client, TEST_PID);
    service->RegisterClientDeathRecipient(client, TEST_PID_OTHER);
    // The second call must have taken the already-registered early return.
    EXPECT_EQ(service->clientInfo_.FindClientPid(client), TEST_PID);
}

/**
 * @tc.name: SensorServiceTest_ProcessDeathObserver_001
 * @tc.desc: A null object is rejected by the promote check without a crash
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_ProcessDeathObserver_001, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    wptr<IRemoteObject> nullObject = nullptr;
    service->ProcessDeathObserver(nullObject); // must not crash
}

/**
 * @tc.name: SensorServiceTest_ProcessDeathObserver_002
 * @tc.desc: A client without a pid mapping (already reclaimed by an earlier delivery)
 *           only runs the broadcast-list cleanup; block policies issued by its pid stay
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_ProcessDeathObserver_002, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> client = new (std::nothrow) IPCObjectStub();
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(service->TransferClientRemoteObject(client), ERR_OK);
    EXPECT_TRUE(InSensorClients(service, client));
    // Simulate the pid mapping already being reclaimed (double delivery of the
    // death notification): only the sensorClients_ entry remains.
    service->clientInfo_.DestroyClientPid(client);
    SetBlockPolicyIssuedByTestPid();
    service->ProcessDeathObserver(client);
    EXPECT_FALSE(InSensorClients(service, client));
    // The invalid-pid branch must not touch the block policy.
    EXPECT_TRUE(SensorDataBlockPolicy::GetInstance().IsSensorDataBlocked(TEST_TARGET_PID, TEST_SENSOR_TYPE));
}

/**
 * @tc.name: SensorServiceTest_ProcessDeathObserver_003
 * @tc.desc: A client with a pid mapping runs the full cleanup: pid mapping, broadcast
 *           list membership and every block policy issued by the client pid are removed
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_ProcessDeathObserver_003, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> client = new (std::nothrow) IPCObjectStub();
    ASSERT_NE(client, nullptr);
    service->RegisterClientDeathRecipient(client, TEST_PID);
    EXPECT_EQ(service->TransferClientRemoteObject(client), ERR_OK);
    SetBlockPolicyIssuedByTestPid();
    service->ProcessDeathObserver(client);
    EXPECT_EQ(service->clientInfo_.FindClientPid(client), TEST_INVALID_PID);
    EXPECT_FALSE(InSensorClients(service, client));
    EXPECT_FALSE(SensorDataBlockPolicy::GetInstance().IsSensorDataBlocked(TEST_TARGET_PID, TEST_SENSOR_TYPE));
}

/**
 * @tc.name: SensorServiceTest_DestroySensorChannel_001
 * @tc.desc: Destroying the data channel must keep the death recipient registered for the
 *           rest of the client process lifetime, so the death observer still reaches the
 *           full cleanup when the process dies
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_DestroySensorChannel_001, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> client = new (std::nothrow) IPCObjectStub();
    ASSERT_NE(client, nullptr);
    service->RegisterClientDeathRecipient(client, TEST_PID);
    EXPECT_EQ(service->DestroySensorChannel(client), ERR_OK);
    // The fix: the death recipient and the pid mapping survive the channel destroy.
    EXPECT_EQ(service->clientInfo_.FindClientPid(client), TEST_PID);
    // And the death observer still reaches the full cleanup path afterwards.
    SetBlockPolicyIssuedByTestPid();
    service->ProcessDeathObserver(client);
    EXPECT_EQ(service->clientInfo_.FindClientPid(client), TEST_INVALID_PID);
    EXPECT_FALSE(SensorDataBlockPolicy::GetInstance().IsSensorDataBlocked(TEST_TARGET_PID, TEST_SENSOR_TYPE));
}

/**
 * @tc.name: SensorServiceTest_DestroySensorChannel_002
 * @tc.desc: Destroying the data channel of a null client is tolerated (the channel
 *           records are keyed by the calling pid only)
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_DestroySensorChannel_002, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> nullClient = nullptr;
    EXPECT_EQ(service->DestroySensorChannel(nullClient), ERR_OK);
}

/**
 * @tc.name: SensorServiceTest_DestroySocketChannel_001
 * @tc.desc: A null client is rejected by the null check
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_DestroySocketChannel_001, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> nullClient = nullptr;
    EXPECT_EQ(service->DestroySocketChannel(nullClient), INVALID_POINTER);
}

/**
 * @tc.name: SensorServiceTest_DestroySocketChannel_002
 * @tc.desc: Destroying the socket channel of a native caller succeeds and keeps the death
 *           recipient registered for the rest of the client process lifetime
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_DestroySocketChannel_002, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> client = new (std::nothrow) IPCObjectStub();
    ASSERT_NE(client, nullptr);
    service->RegisterClientDeathRecipient(client, TEST_PID);
    EXPECT_EQ(service->DestroySocketChannel(client), ERR_OK);
    // The fix: the death recipient and the pid mapping survive the channel destroy.
    EXPECT_EQ(service->clientInfo_.FindClientPid(client), TEST_PID);
    // And the death observer still reaches the full cleanup path afterwards.
    SetBlockPolicyIssuedByTestPid();
    service->ProcessDeathObserver(client);
    EXPECT_EQ(service->clientInfo_.FindClientPid(client), TEST_INVALID_PID);
    EXPECT_FALSE(SensorDataBlockPolicy::GetInstance().IsSensorDataBlocked(TEST_TARGET_PID, TEST_SENSOR_TYPE));
}

/**
 * @tc.name: SensorServiceTest_DestroyClientRemoteObject_001
 * @tc.desc: The explicit remote-object deregistration removes the client from the
 *           broadcast list while leaving the pid mapping untouched
 * @tc.type: FUNC
 */
HWTEST_F(SensorServiceTest, SensorServiceTest_DestroyClientRemoteObject_001, TestSize.Level1)
{
    SensorService *service = GetService();
    ASSERT_NE(service, nullptr);
    sptr<IRemoteObject> client = new (std::nothrow) IPCObjectStub();
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(service->TransferClientRemoteObject(client), ERR_OK);
    EXPECT_EQ(service->DestroyClientRemoteObject(client), ERR_OK);
    EXPECT_FALSE(InSensorClients(service, client));
    // The pid mapping is owned by the death-observer lifetime and stays.
    EXPECT_NE(service->clientInfo_.FindClientPid(client), TEST_INVALID_PID);
}
} // namespace Sensors
} // namespace OHOS
