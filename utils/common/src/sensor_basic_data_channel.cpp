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

#include "sensor_basic_data_channel.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef HIVIEWDFX_HISYSEVENT_ENABLE
#include "hisysevent.h"
#endif // HIVIEWDFX_HISYSEVENT_ENABLE
#include "sensor_errors.h"

#undef LOG_TAG
#define LOG_TAG "SensorBasicChannel"

namespace OHOS {
namespace Sensors {
using namespace OHOS::HiviewDFX;

namespace {
constexpr int32_t SENSOR_READ_DATA_SIZE = sizeof(SensorData) * 100;
constexpr int32_t DEFAULT_CHANNEL_SIZE = 2 * 1024;
constexpr int32_t MAX_RECV_LIMIT = 32;
constexpr int32_t SOCKET_PAIR_SIZE = 2;
constexpr int32_t SEND_RETRY_LIMIT = 5;
constexpr int32_t SEND_RETRY_SLEEP_TIME = 500;
}  // namespace

SensorBasicDataChannel::SensorBasicDataChannel() : sendFd_(-1), receiveFd_(-1), isActive_(false)
{
    SEN_HILOGD("isActive_:%{public}d, sendFd:%{public}d", isActive_, sendFd_);
}

int32_t SensorBasicDataChannel::CreateSensorBasicChannel()
{
    SEN_HILOGI("In");
    std::unique_lock<std::mutex> lock(fdLock_);
    if ((sendFd_ != -1) || (receiveFd_ != -1)) {
        SEN_HILOGD("Already create socketpair");
        return ERR_OK;
    }
    int32_t socketPair[SOCKET_PAIR_SIZE] = { 0 };
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, socketPair) != 0) {
#ifdef HIVIEWDFX_HISYSEVENT_ENABLE
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::SENSOR, "DATA_CHANNEL_EXCEPTION",
            HiSysEvent::EventType::FAULT, "PKG_NAME", "CreateSensorBasicChannel", "ERROR_CODE", errno);
#endif // HIVIEWDFX_HISYSEVENT_ENABLE
        SEN_HILOGE("Create socketpair failed");
        sendFd_ = -1;
        receiveFd_ = -1;
        return SENSOR_CHANNEL_SOCKET_CREATE_ERR;
    }
    fdsan_exchange_owner_tag(socketPair[0], 0, TAG);
    fdsan_exchange_owner_tag(socketPair[1], 0, TAG);
    if (setsockopt(socketPair[0], SOL_SOCKET, SO_SNDBUF, &SENSOR_READ_DATA_SIZE, sizeof(SENSOR_READ_DATA_SIZE)) != 0) {
        SEN_HILOGE("setsockopt socketpair 0, SNDBUF failed, errno:%{public}d", errno);
        goto CLOSE_SOCK;
    }
    if (setsockopt(socketPair[1], SOL_SOCKET, SO_RCVBUF, &SENSOR_READ_DATA_SIZE, sizeof(SENSOR_READ_DATA_SIZE)) != 0) {
        SEN_HILOGE("setsockopt socketpair 1, RCVBUF failed, errno:%{public}d", errno);
        goto CLOSE_SOCK;
    }
    if (setsockopt(socketPair[0], SOL_SOCKET, SO_RCVBUF, &DEFAULT_CHANNEL_SIZE, sizeof(DEFAULT_CHANNEL_SIZE)) != 0) {
        SEN_HILOGE("setsockopt socketpair 0, RCVBUF failed, errno:%{public}d", errno);
        goto CLOSE_SOCK;
    }
    if (setsockopt(socketPair[1], SOL_SOCKET, SO_SNDBUF, &DEFAULT_CHANNEL_SIZE, sizeof(DEFAULT_CHANNEL_SIZE)) != 0) {
        SEN_HILOGE("setsockopt socketpair 1, SNDBUF failed, errno:%{public}d", errno);
        goto CLOSE_SOCK;
    }
    if (fcntl(socketPair[0], F_SETFL, O_NONBLOCK) != 0) {
        SEN_HILOGE("fcntl socketpair 0 failed, errno:%{public}d", errno);
        goto CLOSE_SOCK;
    }
    if (fcntl(socketPair[1], F_SETFL, O_NONBLOCK) != 0) {
        SEN_HILOGE("fcntl socketpair 1 failed, errno:%{public}d", errno);
        goto CLOSE_SOCK;
    }
    sendFd_ = socketPair[0];
    receiveFd_ = socketPair[1];
    SEN_HILOGI("Done");
    return ERR_OK;

    CLOSE_SOCK:
    fdsan_close_with_tag(socketPair[0], TAG);
    fdsan_close_with_tag(socketPair[1], TAG);
    sendFd_ = -1;
    receiveFd_ = -1;
    return SENSOR_CHANNEL_SOCKET_CREATE_ERR;
}

int32_t SensorBasicDataChannel::CreateSensorBasicChannel(MessageParcel &data)
{
    CALL_LOG_ENTER;
    std::unique_lock<std::mutex> lock(fdLock_);
    if (sendFd_ != -1) {
        SEN_HILOGD("Already create socketpair");
        return ERR_OK;
    }
    sendFd_ = data.ReadFileDescriptor();
    fdsan_exchange_owner_tag(sendFd_, 0, TAG);
    if (sendFd_ < 0) {
        SEN_HILOGE("ReadFileDescriptor is failed");
        sendFd_ = -1;
        return SENSOR_CHANNEL_READ_DESCRIPTOR_ERR;
    }
    return ERR_OK;
}

int32_t SensorBasicDataChannel::CreateSensorBasicChannelBySendFd(int32_t sendFd)
{
    CALL_LOG_ENTER;
    std::unique_lock<std::mutex> lock(fdLock_);
    if (sendFd_ != -1) {
        SEN_HILOGD("Already create socketpair");
        return ERR_OK;
    }
    sendFd_ = sendFd;
    fdsan_exchange_owner_tag(sendFd_, 0, TAG);
    if (sendFd_ < 0) {
        SEN_HILOGE("ReadFileDescriptor is failed");
        sendFd_ = -1;
        return SENSOR_CHANNEL_READ_DESCRIPTOR_ERR;
    }
    return ERR_OK;
}

SensorBasicDataChannel::~SensorBasicDataChannel()
{
    DestroySensorBasicChannel();
}

int32_t SensorBasicDataChannel::SendToBinder(MessageParcel &data)
{
    bool result = false;
    {
        std::unique_lock<std::mutex> lock(fdLock_);
        SEN_HILOGD("sendFd:%{public}d", sendFd_);
        if (sendFd_ < 0) {
            SEN_HILOGE("sendFd FileDescriptor error");
            return SENSOR_CHANNEL_SENDFD_ERR;
        }
        result = data.WriteFileDescriptor(sendFd_);
    }
    if (!result) {
        SEN_HILOGE("Send sendFd_ failed");
        CloseSendFd();
        return SENSOR_CHANNEL_WRITE_DESCRIPTOR_ERR;
    }
    return ERR_OK;
}

void SensorBasicDataChannel::CloseSendFd()
{
    std::unique_lock<std::mutex> lock(fdLock_);
    if (sendFd_ != -1) {
        fdsan_close_with_tag(sendFd_, TAG);
        sendFd_ = -1;
        SEN_HILOGD("Close sendFd_");
    }
}

int32_t SensorBasicDataChannel::SendData(const void *vaddr, size_t size)
{
    CHKPR(vaddr, SENSOR_CHANNEL_SEND_ADDR_ERR);
    auto sensorData = reinterpret_cast<const char *>(vaddr);
    int32_t idx = 0;
    int32_t retryCount = 0;
    int32_t buffSize = static_cast<int32_t>(size);
    int32_t remSize = buffSize;
    do {
        std::unique_lock<std::mutex> lock(fdLock_);
        if (sendFd_ < 0) {
            SEN_HILOGE("Failed, param is invalid");
            return SENSOR_CHANNEL_SEND_ADDR_ERR;
        }
        retryCount++;
        ssize_t length = send(sendFd_, &sensorData[idx], remSize, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (length < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                SEN_HILOGD("Continue for EAGAIN|EINTR|EWOULDBLOCK, errno:%{public}d, sendFd_:%{public}d",
                    errno, sendFd_);
                usleep(SEND_RETRY_SLEEP_TIME);
                continue;
            }
            SEN_HILOGE("Send fail, errno:%{public}d, length:%{public}d, sendFd: %{public}d",
                errno, static_cast<int32_t>(length), sendFd_);
            return SENSOR_CHANNEL_SEND_DATA_ERR;
        }
        idx += length;
        remSize -= length;
        if (remSize > 0) {
            usleep(SEND_RETRY_SLEEP_TIME);
        }
    } while (remSize > 0 && retryCount < SEND_RETRY_LIMIT);
    if ((retryCount >= SEND_RETRY_LIMIT) && (remSize > 0)) {
        SEN_HILOGE("Send fail, size:%{public}d, retryCount:%{public}d, idx:%{public}d, "
            "buffSize:%{public}d, errno:%{public}d", buffSize, retryCount, idx, buffSize, errno);
        return SENSOR_CHANNEL_SEND_DATA_ERR;
    }
    return ERR_OK;
}

int32_t SensorBasicDataChannel::ReceiveData(ClientExcuteCB callBack, void *vaddr, size_t size)
{
    if (vaddr == nullptr || callBack == nullptr) {
        SEN_HILOGE("Failed, callBack is null or vaddr is null");
        return ERROR;
    }
    ssize_t length = 0;
    for (int32_t i = 0; i < MAX_RECV_LIMIT; i++) {
        {
            std::unique_lock<std::mutex> lock(fdLock_);
            if (receiveFd_ < 0) {
                SEN_HILOGE("Failed, receiveFd_ invalid");
                return ERROR;
            }
            length = recv(receiveFd_, vaddr, size, MSG_DONTWAIT | MSG_NOSIGNAL);
        }
        if (length > 0) {
            callBack(static_cast<int32_t>(length));
        }
        if (length < 0) {
            if (errno == EINTR) {
                SEN_HILOGD("Continue for EINTR, errno:%{public}d, sendFd_:%{public}d", errno, sendFd_);
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                SEN_HILOGD("No available data");
            } else {
                SEN_HILOGE("recv failed:%{public}s", ::strerror(errno));
                return ERROR;
            }
            return ERR_OK;
        }
    };
    return ERR_OK;
}

int32_t SensorBasicDataChannel::GetSendDataFd()
{
    std::unique_lock<std::mutex> lock(fdLock_);
    return sendFd_;
}

int32_t SensorBasicDataChannel::GetReceiveDataFd()
{
    std::unique_lock<std::mutex> lock(fdLock_);
    return receiveFd_;
}

int32_t SensorBasicDataChannel::DestroySensorBasicChannel()
{
    std::unique_lock<std::mutex> lock(fdLock_);
    if (sendFd_ >= 0) {
        fdsan_close_with_tag(sendFd_, TAG);
        sendFd_ = -1;
        SEN_HILOGD("Close sendFd_ success");
    }
    if (receiveFd_ >= 0) {
        fdsan_close_with_tag(receiveFd_, TAG);
        receiveFd_ = -1;
        SEN_HILOGD("Close receiveFd_ success");
    }
    return ERR_OK;
}

const std::unordered_map<SensorDescription, SensorData> &SensorBasicDataChannel::GetDataCacheBuf() const
{
    return dataCacheBuf_;
}

bool SensorBasicDataChannel::GetSensorStatus() const
{
    return isActive_;
}

void SensorBasicDataChannel::SetSensorStatus(bool isActive)
{
    SEN_HILOGD("isActive_:%{public}d", isActive);
    std::unique_lock<std::mutex> lock(statusLock_);
    isActive_ = isActive;
    return;
}

std::string SensorBasicDataChannel::GetPackageName()
{
    std::unique_lock<std::mutex> lock(pkNameLock_);
    return packageName_;
}

void SensorBasicDataChannel::SetPackageName(std::string packageName)
{
    SEN_HILOGD("SetPackageName in, packageName:%{public}s", packageName.c_str());
    std::unique_lock<std::mutex> lock(pkNameLock_);
    packageName_ = packageName;
}
} // namespace Sensors
} // namespace OHOS
