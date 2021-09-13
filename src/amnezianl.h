#ifndef AMNEZIANL_H
#define AMNEZIANL_H

#include "amnezianl_global.h"
//#include "client/ovpncli.hpp"
#include "client/ovpncli.cpp"
//#include "openvpn/client/clievent.hpp"

class OpenVPNClientAndroid;

class AMNEZIANL_EXPORT Amnezianl
{
public:
    AMNEZIANL_EXPORT Amnezianl();
    AMNEZIANL_EXPORT OpenVPNClientAndroid* getInterfacePointer() const {
        return client;
    }

private:
    OpenVPNClientAndroid* client;
};

class OpenVPNClientAndroid: public openvpn::ClientAPI::OpenVPNClient {
    virtual bool pause_on_connection_timeout();
    virtual void event(const openvpn::ClientAPI::Event &event);
    virtual void log(const openvpn::ClientAPI::LogInfo& loginfo);
    virtual void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest& req);
    virtual void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest& req);
};

#endif // AMNEZIANL_H
