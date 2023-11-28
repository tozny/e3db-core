# Top-level CMake file for Tozny E3DB C-SDK Library and applications

# Mandatory check for CMake version
cmake_minimum_required(VERSION 3.0)

# Project Specifics
project(e3db-c-sdk VERSION 1.0.0 DESCRIPTION sdk LANGUAGES C)

# For all child projects, set include directory path
include_directories(lib)

# For all child projects, set dependent 3rd-party library linkages
# TODO this may change for if not using Linux (i.e. don't include "m")
SET(LIBS_OUTSIDE
    curl ssl crypto m sodium)

# Build library
add_subdirectory(lib)

# Build command-line application
add_subdirectory(cmd)

# Build simple example
add_subdirectory(examples)
