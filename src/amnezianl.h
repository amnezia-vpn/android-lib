#pragma once

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


