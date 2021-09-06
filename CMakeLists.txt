cmake_minimum_required(VERSION 3.14)

project(amnezianl)

#include(${CMAKE_CURRENT_SOURCE_DIR}/deps/CMakeLists.txt)

SET(SSLLIBTYPE STATIC)
SET(OPENSSL_PATH "deps/openvpn/openssl")
set(CMAKE_INCLUDE_CURRENT_DIR ON)

include_directories(deps/openvpn/openssl/include)
include_directories(deps/openvpn/openssl/providers/common/include)
include_directories(deps/openvpn/openssl/providers/implementations/include)
include_directories(deps/openvpn/openssl/providers/implementations/chipers)
include_directories(deps/openvpn/openssl/providers/implementations/keymgmt)

include_directories(deps/openvpn/openssl/include/crypto)

#set(myDesiredRootForHeaderFileSearch deps/openvpn/openssl)
#file(GLOB my_include_directories ${myDesiredRootForHeaderFileSearch})
#include_directories(${my_include_directories})

include_directories(deps/openvpn/lzo/include)

MACRO(HEADER_DIRECTORIES return_list)
    FILE(GLOB_RECURSE new_list *.h)
    SET(dir_list "deps/openvpn/openssl")
    FOREACH(file_path ${new_list})
        GET_FILENAME_COMPONENT(dir_path ${file_path} PATH)
        SET(dir_list ${dir_list} ${dir_path})
    ENDFOREACH()
    LIST(REMOVE_DUPLICATES dir_list)
    SET(${return_list} ${dir_list})
ENDMACRO()

HEADER_DIRECTORIES(header_list)

include_directories(${header_list})

include(deps/openvpn/tools.cmake)
include(deps/openvpn/lzo.cmake)
include(deps/openvpn/lz4.cmake)
include(deps/openvpn/openssl//openssl.cmake)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(amnezianl SHARED
  src/amnezianl_global.h
  src/amnezianl.cpp
  src/amnezianl.h
)

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
#    link_directories(${CMAKE_SOURCE_DIR}/)
    target_link_libraries(amnezianl crypto
                                ssl
                                lzo
                                lz4)
else ()
    target_compile_definitions(ovpn3 PRIVATE
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
#        -DGIT_VERSION_STRING=\"${OPENVPN3_GIT}\"
        -DNO_ROUTE_EXCLUDE_EMULATION
        -DOPENVPN_SHOW_SESSION_TOKEN
#        -DOPENSSL_API_COMPAT=0x10200000L
        )


#add_dependencies(amnezianl deps)
target_compile_definitions(amnezianl PRIVATE AMNEZIANL_LIBRARY)
#target_link_libraries(amnezianl ovpn3)
