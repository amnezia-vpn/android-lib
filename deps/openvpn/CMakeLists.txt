cmake_minimum_required(VERSION 3.14)
# Git version string
project(openvpn_deps)

#include(GetGitRevisionDescription.cmake)
#git_describe(OPENVPN3_GIT "${CMAKE_CURRENT_SOURCE_DIR}/openvpn3" "--tags" "--always" "--long")
#message("OpenVPN 3.x version ${OPENVPN3_GIT}")

# Set mbedtls options
OPTION(ENABLE_PROGRAMS "" OFF)
OPTION(USE_SHARED_MBEDTLS_LIBRARY "" OFF)
OPTION(ENABLE_TESTING "" OFF)

# Own options
OPTION(OPENVPN2MBED "Use mbed TLS for OpenVPN2" OFF)
OPTION(OPENVPN3OSSL "Use OpenSSL for OpenVPN3" ON)
SET(OPENVPN3OSSL ON)

# STATIC or SHARED
SET(SSLLIBTYPE STATIC)
SET(OPENSSL_PATH "openssl")

include(tools.cmake)
include(lzo.cmake)
include(lz4.cmake)
include(openssl//openssl.cmake)
message("ABI: ${CMAKE_ANDROID_ARCH_ABI}")
set(ANDROID_EXTRA_LIBS "")
message("${ANDROID_EXTRA_LIBS}")

if(NOT ${OPENVPN3OSSL} OR ${OPENVPN2MBED})
    add_subdirectory(mbedtls)
endif()
