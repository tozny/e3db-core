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
endif()

# Enable below for debugging memory issues.
# add_compile_options("-g")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
# set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address")

# Use a hard-coded configuration
if(USE_HARDCODED_CONFIG_JSON)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-DUSE_HARDCODED_CONFIG_JSON=1")
endif()

# Build library, command-line application, and simple example
add_subdirectory(lib)
add_subdirectory(cmd)
add_subdirectory(examples)
