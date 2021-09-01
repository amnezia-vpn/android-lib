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

set(ovpn3_SRCS
        openvpn3/client/ovpncli.cpp)

add_library(ovpn3 SHARED ${ovpn3_SRCS})

target_include_directories(ovpn3 PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/lzo/include
        ${CMAKE_CURRENT_SOURCE_DIR}/openvpn3
        ${CMAKE_CURRENT_SOURCE_DIR}/asio/asio/include
        ${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/client
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include
        )

if (${OPENVPN3OSSL})
    target_compile_definitions(ovpn3 PRIVATE
            -DUSE_OPENSSL
            )
    target_link_libraries(ovpn3 crypto
                                ssl
                                lzo
                                lz4)
else ()
    target_compile_definitions(ovpn3 PRIVATE
            -DUSE_MBEDTLS
            )
    target_link_libraries(ovpn3 mbedtls mbedx509 mbedcrypto lzo lz4)
endif ()

target_compile_options(ovpn3 PRIVATE -std=c++1y)
target_compile_definitions(ovpn3 PRIVATE
        -DHAVE_CONFIG_H
        -DHAVE_LZO
        -DHAVE_LZ4
        -DASIO_STANDALONE
        -DUSE_ASIO
#        -DGIT_VERSION_STRING=\"${OPENVPN3_GIT}\"
        -DNO_ROUTE_EXCLUDE_EMULATION
        -DOPENVPN_SHOW_SESSION_TOKEN
#        -DOPENSSL_API_COMPAT=0x10200000L
        )


