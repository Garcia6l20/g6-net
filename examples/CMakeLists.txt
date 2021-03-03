option(G6_NET_BUILD_EXAMPLES "Build g6-net examples" ON)
if(NOT G6_NET_BUILD_EXAMPLES)
  return()
endif()

find_package(fmt REQUIRED)

link_libraries(g6::net fmt::fmt)
add_executable(${PROJECT_NAME}-tcp-example tcp-example.cpp)
add_executable(${PROJECT_NAME}-udp-example udp-example.cpp)
