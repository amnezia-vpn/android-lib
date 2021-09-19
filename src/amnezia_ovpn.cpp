#include "amnezia_ovpn.h"
#include "client/ovpncli.hpp"

using namespace openvpn::ClientAPI;

class AmneziaOpenVPN : public openvpn::ClientAPI::OpenVPNClient {

    void event(const Event & event) override
    {

    }

    void log(const LogInfo & log) override
    {

    }

    bool pause_on_connection_timeout() override
    {

    }

    void external_pki_cert_request(ExternalPKICertRequest&) override
    {

    }

    void external_pki_sign_request(ExternalPKISignRequest&) override
    {

    }

};

static AmneziaOpenVPN * ovpn_instance;


AmneziaVPN::OpenVPNProtocol::OpenVPNProtocol()
{
    if(ovpn_instance != nullptr)
        delete ovpn_instance;

    ovpn_instance = new AmneziaOpenVPN();
}

bool AmneziaVPN::OpenVPNProtocol::isConnected() const
{

}

bool AmneziaVPN::OpenVPNProtocol::isDisconnected() const
{

}

AmneziaVPN::ErrorCode AmneziaVPN::OpenVPNProtocol::start()
{
    // Configure connection before connect
    ovpn_instance->connect();
}

void AmneziaVPN::OpenVPNProtocol::stop()
{
    ovpn_instance->stop();
}

AmneziaVPN::ConnectionState AmneziaVPN::OpenVPNProtocol::connectionState() const
{

}
