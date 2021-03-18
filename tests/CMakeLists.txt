if(NOT BUILD_TESTING)
  return()
endif()

find_package(fmt REQUIRED)
link_libraries(g6::net fmt::fmt)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_subdirectory(file)
add_subdirectory(net)
