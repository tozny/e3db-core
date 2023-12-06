# Top-level CMake file for Tozny E3DB C-SDK Library and applications

# Mandatory check for CMake version
cmake_minimum_required(VERSION 3.0)

# Project Specifics
project(e3db-c-sdk VERSION 1.0.0 DESCRIPTION sdk LANGUAGES C)

# Set include directory path for all child projects
include_directories(lib)

# Set dependent 3rd-party library linkages
if(UNIX AND NOT APPLE)
    find_package(tiny-curl REQUIRED)
    list(APPEND LIBS_OUTSIDE ${TINY_CURL_LIBRARIES})
else()
    list(APPEND LIBS_OUTSIDE curl)
endif()

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
    list(APPEND LIBS_OUTSIDE sodium mbedtls)
endif()

# Build library, command-line application, and simple example
add_subdirectory(lib)
add_subdirectory(cmd)
add_subdirectory(examples)
