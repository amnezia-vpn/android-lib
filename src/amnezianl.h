#ifndef AMNEZIANL_H
#define AMNEZIANL_H

#include "amnezianl_global.h"

class OpenVPNProtocol;

class AMNEZIANL_EXPORT Amnezianl
{
public:
    AMNEZIANL_EXPORT Amnezianl();
    AMNEZIANL_EXPORT OpenVPNProtocol* getInterfacePointer() const {
        return client;
    }

private:
    OpenVPNProtocol* client;
};


namespace AmneziaVPN {
    enum class ErrorCode {
        OK = 0,
        Error
    };

    enum class ConnectionState {
        Connected = 0,
        Disconnected
    };

    class VPNProtocol
    {

    public:
        VPNProtocol();
        virtual ~VPNProtocol();
        virtual bool isConnected() const;
        virtual bool isDisconnected() const;
        virtual ErrorCode start() = 0;
        virtual void stop() = 0;
        virtual ConnectionState connectionState() const;
    };

    class WireGuardProtocol : public VPNProtocol {
        WireGuardProtocol();

        bool isConnected() const override;
        bool isDisconnected() const override;
        ErrorCode start() override;
        void stop() override;
        ConnectionState connectionState() const override;
    };

    class ShadowSocksProtocol : public VPNProtocol {
        ShadowSocksProtocol();

        bool isConnected() const override;
        bool isDisconnected() const override;
        ErrorCode start() override;
        void stop() override;
        ConnectionState connectionState() const override;
    };
}

#endif // AMNEZIANL_H
