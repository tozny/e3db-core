# FindSodium.cmake
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY sodium)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium DEFAULT_MSG SODIUM_LIBRARY SODIUM_INCLUDE_DIR)
