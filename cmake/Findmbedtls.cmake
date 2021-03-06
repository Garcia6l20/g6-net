find_path(MBEDTLS_INCLUDE_DIRS mbedtls/config.h)

find_library(MBEDTLS_TLS_LIB mbedtls)
find_library(MBEDTLS_CRYPTO_LIB mbedcrypto)
find_library(MBEDTLS_X509_LIB mbedx509)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(mbedtls "Cannot find mbedTLS"
  MBEDTLS_INCLUDE_DIRS
  MBEDTLS_TLS_LIB
  MBEDTLS_CRYPTO_LIB
  MBEDTLS_X509_LIB
  )

mark_as_advanced(
  MBEDTLS_INCLUDE_DIRS
  MBEDTLS_TLS_LIB
  MBEDTLS_CRYPTO_LIB
  MBEDTLS_X509_LIB
)

add_library(_mbed_tls INTERFACE IMPORTED GLOBAL)
target_include_directories(_mbed_tls INTERFACE ${MBEDTLS_INCLUDE_DIRS})
target_link_libraries(_mbed_tls INTERFACE ${MBEDTLS_TLS_LIB})
add_library(mbed::tls ALIAS _mbed_tls)

add_library(_mbed_crypto INTERFACE IMPORTED GLOBAL)
target_include_directories(_mbed_crypto INTERFACE ${MBEDTLS_INCLUDE_DIRS})
target_link_libraries(_mbed_crypto INTERFACE ${MBEDTLS_CRYPTO_LIB})
add_library(mbed::crypto ALIAS _mbed_crypto)

add_library(_mbed_x509 INTERFACE IMPORTED GLOBAL)
target_include_directories(_mbed_x509 INTERFACE ${MBEDTLS_INCLUDE_DIRS})
target_link_libraries(_mbed_x509 INTERFACE ${MBEDTLS_X509_LIB})
add_library(mbed::x509 ALIAS _mbed_x509)
