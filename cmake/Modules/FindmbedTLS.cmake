# FindmbedTLS.cmake
# This module looks for the mbedTLS library.
find_path(MBEDTLS_INCLUDE_DIR mbedtls/base64.h
  PATH_SUFFIXES include mbedtls
  PATHS /usr/local/opt/mbedtls/include /usr/local/Cellar/mbedtls/3.5.1/include
)
find_library(MBEDTLS_LIBRARY
  NAMES mbedtls mbedcrypto
  PATH_SUFFIXES lib
  PATHS /usr/local/opt/mbedtls/lib  /usr/local/Cellar/mbedtls/3.5.1/lib
)
if (MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARY)
  set(MBEDTLS_FOUND TRUE)
  set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY})
  set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
else()
  set(MBEDTLS_FOUND FALSE)
  set(MBEDTLS_LIBRARIES "")
  set(MBEDTLS_INCLUDE_DIRS "")
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(mbedTLS DEFAULT_MSG MBEDTLS_LIBRARIES MBEDTLS_INCLUDE_DIRS)
