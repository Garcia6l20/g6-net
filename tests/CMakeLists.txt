if(NOT BUILD_TESTING)
  return()
endif()

find_package(Catch2 REQUIRED)

add_library(${PROJECT_NAME}-tests-main main.cpp)
target_link_libraries(${PROJECT_NAME}-tests-main PUBLIC Catch2::Catch2)

##
## add_test overload
##
## add_test(BASE_TEST_SOURCE [EXTRA_SOURCE_FILE...])
##
function(add_test _base_test_source)

  get_filename_component(_name "${_base_test_source}" NAME_WE)

  set(_arg_options )
  set(_arg_one_value_options )
  set(_arg_multi_value_options )
  cmake_parse_arguments(ARG "${_arg_options}" "${_arg_one_value_options}" "${_arg_multi_value_options}" ${ARGN})

  set(_target ${PROJECT_NAME}-${_name})

  add_executable(${_target} ${_name}.cpp ${ARG_UNPARSED_ARGUMENTS})
  target_link_libraries(${_target} PRIVATE ${PROJECT_NAME}-tests-main g6::net)

  _add_test(NAME ${PROJECT_NAME}-${_name} COMMAND ${PROJECT_NAME}-${_name})

endfunction()

add_test(udp-test.cpp)
