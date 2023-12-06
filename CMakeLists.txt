# Top-level CMake file for Tozny E3DB C-SDK Library and applications

# Mandatory check for CMake version
cmake_minimum_required(VERSION 3.0)

# Project Specifics
project(e3db-c-sdk VERSION 1.0.0 DESCRIPTION sdk LANGUAGES C)

# For all child projects, set include directory path
include_directories(lib)

# For all child projects, set dependent 3rd-party library linkages
SET(LIBS_OUTSIDE curl m)

# Check if the platform is macOS (Darwin)
if(APPLE)
    # Use the FindSodium module
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
    find_package(Sodium REQUIRED)

    # Check if Sodium is found
    if(SODIUM_FOUND)
        # Include Sodium directories
        include_directories(${SODIUM_INCLUDE_DIR})

        # Add Sodium libraries to the list
        SET(LIBS_OUTSIDE ${LIBS_OUTSIDE} ${SODIUM_LIBRARY})
    endif()
    # Find OpenSSL package
    find_package(OpenSSL REQUIRED)

    # Check if OpenSSL is found
    if(OPENSSL_FOUND)
        # Include OpenSSL directories
        include_directories(${OPENSSL_INCLUDE_DIR})

        # Add OpenSSL libraries to the list
        SET(LIBS_OUTSIDE ${LIBS_OUTSIDE} ${OPENSSL_LIBRARIES})
    endif()
else()
    # Non-Apple platforms
    SET(LIBS_OUTSIDE ${LIBS_OUTSIDE} sodium ssl crypto)
endif()

# Build library
add_subdirectory(lib)

# Build command-line application
add_subdirectory(cmd)

# Build simple example
add_subdirectory(examples)
