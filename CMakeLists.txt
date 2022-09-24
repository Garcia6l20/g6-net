cmake_minimum_required(VERSION 3.16)

if (NOT G6_CMAKE)
  include(FetchContent)
  FetchContent_declare(g6-cmake-fetch
    GIT_REPOSITORY https://github.com/Garcia6L20/g6-cmake.git
    GIT_TAG main)
  FetchContent_makeAvailable(g6-cmake-fetch)
endif()

project(g6-net
  LANGUAGES CXX
  VERSION 0.0.1
  )

set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake ${CMAKE_BINARY_DIR})

##
## Dependencies
##
if (NOT TARGET g6-coro)
  add_subdirectory(external/g6-coro)
endif()

find_package(MbedTLS REQUIRED)
find_package(fmt REQUIRED)
find_package(ctre REQUIRED)

##
##
##

file(GLOB_RECURSE ${PROJECT_NAME}_headers include/)

add_library(${PROJECT_NAME}

  src/context.cpp
  src/ip_address.cpp
  src/ip_endpoint.cpp
  src/ipv4_address.cpp
  src/ipv4_endpoint.cpp
  src/ipv6_address.cpp
  src/ipv6_endpoint.cpp
  src/ssl_async_socket.cpp

  ${${PROJECT_NAME}_headers}
  )
set_target_properties(${PROJECT_NAME} PROPERTIES
  EXPORT_NAME net)
add_library(g6::net ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)

if (NOT TARGET MbedTLS::MbedTLS)
  add_library(MbedTLS::MbedTLS INTERFACE IMPORTED GLOBAL)
  target_link_libraries(MbedTLS::MbedTLS INTERFACE MbedTLS::mbedcrypto MbedTLS::mbedx509 MbedTLS::mbedtls)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC g6::coro fmt::fmt MbedTLS::MbedTLS)

option(G6_NO_IO_URING "Disable IO uring as default context" OFF)
if (G6_NO_IO_URING)
  target_compile_definitions(${PROJECT_NAME} PUBLIC G6_NO_IO_URING=true)
endif()

if(WIN32)
  target_link_libraries(${PROJECT_NAME} PUBLIC wsock32 ws2_32)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(examples)

enable_testing()
if (BUILD_TESTING)
  add_subdirectory(tests)
endif()

install(TARGETS ${PROJECT_NAME} 
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include
  FILES_MATCHING PATTERN *)
