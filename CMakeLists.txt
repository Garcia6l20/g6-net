cmake_minimum_required(VERSION 3.17)
project(g6-net
  LANGUAGES CXX
  VERSION 0.0.1
  )

set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake ${CMAKE_BINARY_DIR})

##
## Dependencies
##
option(G6_UNIFEX_DEVEL "Enable unifex development" OFF)
set(_BUILD_TESTING ${BUILD_TESTING})
if (NOT G6_UNIFEX_DEVEL)
  set(BUILD_TESTING OFF)
endif()
set(UNIFEX_BUILD_EXAMPLES ${G6_UNIFEX_DEVEL})
add_subdirectory(external/libunifex)
set(BUILD_TESTING ${_BUILD_TESTING})

##
##
##

file(GLOB_RECURSE ${PROJECT_NAME}_headers include/)

add_library(${PROJECT_NAME}
  src/ip_address.cpp
  src/ip_endpoint.cpp
  src/ipv4_address.cpp
  src/ipv4_endpoint.cpp
  src/ipv6_address.cpp
  src/ipv6_endpoint.cpp

  ${${PROJECT_NAME}_headers}
  )
add_library(g6::net ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} PUBLIC unifex)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(examples)

enable_testing()
if (BUILD_TESTING)
  add_subdirectory(tests)
endif()
