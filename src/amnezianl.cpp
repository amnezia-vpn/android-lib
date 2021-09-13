#include "amnezianl.h"

Amnezianl::Amnezianl()
{
    client = new OpenVPNClientAndroid;
}

bool OpenVPNClientAndroid::pause_on_connection_timeout() {
    return false;
}

void OpenVPNClientAndroid::event(const openvpn::ClientAPI::Event &event) {
    bool error = event.error;
    std::string name = event.name;
    std::string info = event.info;
    std::cout << "EVENT: err=" << error << "\n";
    std::cout << "EVENT: name=" << name << "\n";
    std::cout << "EVENT: info=" << info << "\n";
}

void OpenVPNClientAndroid::log(const openvpn::ClientAPI::LogInfo& loginfo) {
    std::string text = loginfo.text;
    std::cout << "LOG: " << text;
}

void OpenVPNClientAndroid::external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest& req) {
    req.error = true;
    req.errorText = "cert request failed: external PKI not implemented";
}

void OpenVPNClientAndroid::external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest& req) {
    req.error = true;
    req.errorText = "sign request failed: external PKI not implemented";
}
