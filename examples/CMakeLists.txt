# CMake file for Tozny E3DB C-SDK Simple Example

# Glob the source and header files
file(GLOB EXE_SOURCES *.c)
file(GLOB EXE_HEADERS *.h)

# Set dependent 3rd-party library linkages
set(LIBS_OUTSIDE curl m)

# Check if the platform is macOS (Darwin)
if(APPLE)
    # Find Sodium and mbedTLS packages
    find_package(Sodium REQUIRED)

    # Check if Sodium is found
    if(SODIUM_FOUND)
        # Include Sodium directories
        include_directories(${SODIUM_INCLUDE_DIR})

        # Add Sodium libraries to the list
        SET(LIBS_OUTSIDE ${LIBS_OUTSIDE} ${SODIUM_LIBRARY})
    endif()

    # Find mbedTLS package
    find_package(mbedTLS REQUIRED)

    # Check if mbedTLS is found
    if(MBEDTLS_FOUND)
        # Include mbedTLS directories
        include_directories(${MBEDTLS_INCLUDE_DIRS})

        # Add mbedTLS libraries to the list
        SET(LIBS_OUTSIDE ${LIBS_OUTSIDE} ${MBEDTLS_LIBRARIES})
    endif()
else()
    # Non-Apple platforms
    SET(LIBS_OUTSIDE ${LIBS_OUTSIDE} sodium mbedtls)
endif()

# Add sources and make executable "simple" (or "simple.exe")
add_executable(simple
               ${EXE_SOURCES}
               ${EXE_HEADERS})

# Add sources and make executable "simple" (or "simple.exe")
add_executable(simple ${EXE_SOURCES} ${EXE_HEADERS})


# Specify the default library directory
set(DEFAULT_LIBRARY_DIR /usr/local/opt/mbedtls/lib)

# Check if a specific file exists
file(GLOB LIBRARY_SPECIAL_CHECK /opt/homebrew/Cellar/mbedtls/3.5.1/lib/libmbedtls.a)
if(LIBRARY_SPECIAL_CHECK)
   # Target-specific libraries for the other computer
    target_link_libraries(simple e3db_lib ${LIBS_OUTSIDE}
                          /opt/homebrew/Cellar/mbedtls/3.5.1/lib/libmbedtls.a
                          /opt/homebrew/Cellar/mbedtls/3.5.1/lib/libmbedcrypto.a
                          /opt/homebrew/Cellar/mbedtls/3.5.1/lib/libmbedx509.a)
    
    # Target-specific library search path for the other computer
    link_directories(/opt/homebrew/Cellar/mbedtls/3.5.1/lib)
else()
    # Default libraries and library search path
    target_link_libraries(simple e3db_lib ${LIBS_OUTSIDE}
                          /usr/local/opt/mbedtls/lib/libmbedtls.a
                          /usr/local/opt/mbedtls/lib/libmbedcrypto.a
                          /usr/local/opt/mbedtls/lib/libmbedx509.a)
    
    # Default library search path
    link_directories(${DEFAULT_LIBRARY_DIR})
endif()
