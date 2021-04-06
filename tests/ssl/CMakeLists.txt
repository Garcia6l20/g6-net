# key/cert generation script
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/gen_cert_hpp.cmake "
execute_process(COMMAND ${MBEDTLS_GEN_KEY_EXE} filename=test.key)
execute_process(COMMAND ${MBEDTLS_CERT_WRITE_EXE} selfsign=1 is_ca=1 issuer_key=test.key issuer_name=CN=localhost output_file=test.crt)

execute_process(
  COMMAND ${CMAKE_COMMAND} -E cat test.key
  OUTPUT_VARIABLE KEY
  OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(
  COMMAND ${CMAKE_COMMAND} -E cat test.crt
  OUTPUT_VARIABLE CERT
  OUTPUT_STRIP_TRAILING_WHITESPACE)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cert.hpp.in cert.hpp @ONLY)
")

add_custom_command(OUTPUT cert.hpp
  COMMAND cmake -P gen_cert_hpp.cmake
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

set(CMAKE_INCLUDE_CURRENT_DIR ON)

g6_add_unit_test(ssl-test.cpp TARGET ssl-test)
target_sources(${ssl-test} PRIVATE cert.hpp)
g6_add_unit_test(ssl-tcp-test.cpp TARGET ssl-tcp-test)
target_sources(${ssl-tcp-test} PRIVATE cert.hpp)
