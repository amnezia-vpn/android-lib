#pragma once

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
        VPNProtocol() = default;
        virtual bool isConnected() const = 0;
        virtual bool isDisconnected() const = 0;
        virtual ErrorCode start() = 0;
        virtual void stop() = 0;
        virtual ConnectionState connectionState() const = 0;
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

