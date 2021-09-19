#pragma once

#include "amnezianl.h"

namespace AmneziaVPN {

class OpenVPNProtocol : public VPNProtocol {
    OpenVPNProtocol();

    bool isConnected() const override;
    bool isDisconnected() const override;
    ErrorCode start() override;
    void stop() override;
    ConnectionState connectionState() const override;
};

}
