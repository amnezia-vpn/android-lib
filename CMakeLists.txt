cmake_minimum_required(VERSION 3.14)

project(amnezianl)

include(${CMAKE_CURRENT_SOURCE_DIR}/deps/CMakeLists.txt)

add_library(amnezianl SHARED
  src/amnezianl_global.h
  src/amnezianl.cpp
  src/amnezianl.h
  src/amnezia_ovpn.h
  src/amnezia_ovpn.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/openvpn/openvpn3/client/ovpncli.cpp
)

set_target_properties(amnezianl PROPERTIES LINKER_LANGUAGE CXX)

target_include_directories(amnezianl PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/openvpn/lzo/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/openvpn/openvpn3
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/openvpn/asio/asio/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/openvpn/openvpn3/client
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/openvpn/mbedtls/include
        )


if (${OPENVPN3OSSL})
    target_compile_definitions(amnezianl PRIVATE
            -DUSE_OPENSSL
            )

    target_link_libraries(amnezianl crypto
                                ssl
                                lzo
                                lz4)
else ()
    target_compile_definitions(amnezianl PRIVATE
            -DUSE_MBEDTLS
            )
    target_link_libraries(amnezianl mbedtls mbedx509 mbedcrypto lzo lz4)
endif ()

target_compile_options(amnezianl PRIVATE -std=c++1y)
target_compile_definitions(amnezianl PRIVATE
        -DHAVE_CONFIG_H
        -DHAVE_LZO
        -DHAVE_LZ4
        -DASIO_STANDALONE
        -DUSE_ASIO
        -DNO_ROUTE_EXCLUDE_EMULATION
        -DOPENVPN_SHOW_SESSION_TOKEN
        )


target_compile_definitions(amnezianl PRIVATE AMNEZIANL_LIBRARY)
