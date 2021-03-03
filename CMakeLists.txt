cmake_minimum_required(VERSION 3.17)
project(g6-net)

set(CMAKE_CXX_STANDARD 20)

##
## Dependencies
##
add_subdirectory(external/libunifex)

##
##
##

add_library(${PROJECT_NAME}
  src/ip_address.cpp
  src/ip_endpoint.cpp
  src/ipv4_address.cpp
  src/ipv4_endpoint.cpp
  src/ipv6_address.cpp
  src/ipv6_endpoint.cpp)
add_library(g6::net ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} PUBLIC unifex)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(tests)
add_subdirectory(examples)