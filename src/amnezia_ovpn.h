#pragma once

#include "amneziainterface.h"
#include <string>
namespace AmneziaVPN {

class OpenVPNProtocol : public VPNProtocol {
public:
    OpenVPNProtocol(std::string &configData);

    bool isConnected() const override;
    bool isDisconnected() const override;
    ErrorCode start() override;
    void stop() override;
    ConnectionState connectionState() const override;
    std::string returnStatus();
protected:
    std::string m_configData;
};

}
