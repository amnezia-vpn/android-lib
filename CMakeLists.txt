cmake_minimum_required(VERSION 3.14)

project(amnezianl LANGUAGES CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/deps/CMakeLists.txt)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(amnezianl SHARED
  src/amnezianl_global.h
  src/amnezianl.cpp
  src/amnezianl.h
)

#add_dependencies(amnezianl deps)
target_compile_definitions(amnezianl PRIVATE AMNEZIANL_LIBRARY)
target_link_libraries(amnezianl ovpn3)
