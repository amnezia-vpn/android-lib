#include "amnezia_ovpn.h"
#include "client/ovpncli.hpp"

using namespace openvpn::ClientAPI;

namespace AmneziaVPN {
    class AmneziaOpenVPN : public OpenVPNClient {

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


    OpenVPNProtocol::OpenVPNProtocol()
        : VPNProtocol()
    {
        if(ovpn_instance != nullptr)
            delete ovpn_instance;

        ovpn_instance = new AmneziaOpenVPN();
    }

    bool OpenVPNProtocol::isConnected() const
    {

    }

    bool OpenVPNProtocol::isDisconnected() const
    {

    }

    ErrorCode OpenVPNProtocol::start()
    {
        // Configure connection before connect
        ovpn_instance->connect();
    }

    void OpenVPNProtocol::stop()
    {
        ovpn_instance->stop();
    }

    ConnectionState OpenVPNProtocol::connectionState() const
    {

    }

};

