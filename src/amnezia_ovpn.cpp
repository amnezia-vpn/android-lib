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
    bool setConfig(const std::string& lConfigData)
    {
        Config lConfig;

        lConfig.content = lConfigData;

        ProvideCreds lCreds;
        //username from config or GUI
        lCreds.username = "user";
        //password from config or GUI
        lCreds.password = "pass!";

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


    bool tun_builder_new() override
    {
        return false;
    }

    bool tun_builder_set_layer(int layer) override
    {
        return true;
    }


    bool tun_builder_set_remote_address(const std::string& address, bool ipv6) override
    {
        return false;
    }

    bool tun_builder_add_address(const std::string& address,
                                 int prefix_length,
                                 const std::string& gateway, // optional
                                 bool ipv6,
                                 bool net30) override
    {
        return false;
    }

    bool tun_builder_reroute_gw(bool ipv4,
                                bool ipv6,
                                unsigned int flags) override
    {
        return false;
    }


    bool tun_builder_add_route(const std::string& address,
                               int prefix_length,
                               int metric,
                               bool ipv6) override
    {
        return false;
    }

    bool tun_builder_add_dns_server(const std::string& address, bool ipv6) override
    {
        return false;
    }

    bool tun_builder_add_search_domain(const std::string& domain) override
    {
        return false;
    }

    bool tun_builder_set_mtu(int mtu) override
    {
        return false;
    }

    bool tun_builder_set_session_name(const std::string& name) override
    {
        return false;
    }

    bool tun_builder_set_proxy_http(const std::string& host, int port) override
    {
        return false;
    }

    bool tun_builder_set_proxy_https(const std::string& host, int port) override
    {
        return false;
    }

    int tun_builder_establish() override
    {
        return -1;
    }

    const std::vector<std::string> tun_builder_get_local_networks(bool ipv6) override
    {
        return {};
    }


};

static AmneziaOpenVPN * ovpn_instance;


OpenVPNProtocol::OpenVPNProtocol(std::string &configData)
    : VPNProtocol(), m_configData(configData)
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
    ovpn_instance->setConfig(m_configData);
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
    if(!ovpn_instance->setConfig(m_configData))
    {
        return "Cannot set config";
    }
    Status status = ovpn_instance->connect();

    return "Status: "+ status.status + " Messge: " + status.message;


}
};

