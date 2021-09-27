#include <iostream>
#include <fstream>
#include "amnezia_ovpn.h"
#include "client/ovpncli.hpp"

using namespace openvpn::ClientAPI;

#include <openvpn/time/timestr.hpp>

using namespace openvpn;

namespace AmneziaVPN {
    class AmneziaOpenVPN : public OpenVPNClient {
    public:
        bool setConfig(const std::string& aConfigFileName)
        {
            std::ifstream lConfigFile;

            lConfigFile.open(aConfigFileName);

            if (lConfigFile.is_open() == false) {
                return false;
            }

            std::string lConfigData{};

            std::stringstream lFileStream;
            lFileStream << lConfigFile.rdbuf();
            lConfigData = lFileStream.str();

            Config lConfig;

            lConfig.content = lConfigData;

            ProvideCreds lCreds;
            //username from config or GUI
            lCreds.username = "user"; //temp
             //password from config or GUI
            lCreds.password = "pass"; //temp

            provide_creds(lCreds);

            EvalConfig lEval = eval_config(lConfig);

            return lEval.error == false;
        }

        void event(const Event & event) override
        {
            if (event.name == "CONNECTED") {
                std::cout << "VPN connected succesfully" << std::endl;
            }
        }

        void log(const LogInfo & log) override
        {
             std::cout << date_time() << ' ' << log.text << std::flush;
        }

        bool pause_on_connection_timeout() override
        {
            return false;
        }

        void external_pki_cert_request(ExternalPKICertRequest&) override
        {
               //not impl
        }

        void external_pki_sign_request(ExternalPKISignRequest&) override
        {
              //not impl
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
        ovpn_instance->setConfig("path/to/config.ovpn");
        ovpn_instance->connect();
        return ErrorCode::OK;
    }

    void OpenVPNProtocol::stop()
    {
        ovpn_instance->stop();
    }

    ConnectionState OpenVPNProtocol::connectionState() const
    {

    }

    std::string OpenVPNProtocol::returnStatus()
    {
        // TEMP
        ovpn_instance->setConfig("path/to/config.ovpn");
        Status status = ovpn_instance->connect();

        if (status.error)
        {
            return "Status: "+ status.status + " Messge: " + status.message;
        }

        return "Success";

    }
};

