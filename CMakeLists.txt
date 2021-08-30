cmake_minimum_required(VERSION 3.14)

project(amnezianl LANGUAGES CXX)

add_subdirectory(deps)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(amnezianl SHARED
  src/amnezianl_global.h
  src/amnezianl.cpp
  src/amnezianl.h
)

target_compile_definitions(amnezianl PRIVATE AMNEZIANL_LIBRARY)
target_link_libraries(amnezianl ovpn3)
