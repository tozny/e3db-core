# Top-level CMake file for Tozny E3DB C-SDK Library and applications

# Mandatory check for CMake version
cmake_minimum_required(VERSION 3.0)

# Project Specifics
project(e3db-c-sdk VERSION 1.0.0 DESCRIPTION sdk LANGUAGES C)

# Set include directory path for all child projects
include_directories(lib)

# Set dependent 3rd-party library linkages
set(LIBS_OUTSIDE m)

# Check if the platform is macOS (Darwin)
if(APPLE)
    # Use the FindSodium module
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
    find_package(Sodium REQUIRED)

    # Check if Sodium is found
    if(SODIUM_FOUND)
        # Include Sodium directories
        include_directories(${SODIUM_INCLUDE_DIR})
        list(APPEND LIBS_OUTSIDE ${SODIUM_LIBRARY})
    endif()

    # Find mbedTLS package
    find_package(mbedTLS REQUIRED)

    # Check if mbedTLS is found
    if(MBEDTLS_FOUND)
        # Include mbedTLS directories
        include_directories(${MBEDTLS_INCLUDE_DIRS})
        list(APPEND LIBS_OUTSIDE ${MBEDTLS_LIBRARIES})
    endif()
else()
    # Non-Apple platforms

    # Build and use local copy of mbedTLS
    add_subdirectory(mbedtls)
    set(MBEDTLS_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/mbedtls/include")
    include_directories(${MBEDTLS_INCLUDE_DIRS})
    set(MBEDTLS_LIB_BUILD_DIR "${CMAKE_BINARY_DIR}/mbedtls/library")
    set(MBEDTLS_LIBS  ${MBEDTLS_LIB_BUILD_DIR}/libmbedtls.a
                    ${MBEDTLS_LIB_BUILD_DIR}/libmbedcrypto.a
                    ${MBEDTLS_LIB_BUILD_DIR}/libmbedx509.a)
    
    # Build and use local copy of Sodium library
    add_subdirectory(libsodium-cmake)
    include_directories(${LIBSODIUM_INCLUDE_DIR})
    set(LIBSODIUM_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/libsodium-cmake/libsodium/src/libsodium/include/")
    set(LIBSODIUM_LIB_BUILD_DIR "${CMAKE_BINARY_DIR}/libsodium-cmake")
    set(LIBSODIUM_LIB "${LIBSODIUM_LIB_BUILD_DIR}/libsodium.a")
endif()

# Enable below for debugging memory issues.
# add_compile_options("-g")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
# set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address")

# Build library, command-line application, and simple example
add_subdirectory(lib)
add_subdirectory(cmd)
add_subdirectory(examples)
