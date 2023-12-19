# CMake file for Tozny E3DB C-SDK Command Line Interface

# Glob the source and header files
file(GLOB EXE_SOURCES *.c)
file(GLOB EXE_HEADERS *.h)

# Check if the platform is macOS (Darwin)
if(APPLE)
    # Find and include Sodium package
    find_package(Sodium REQUIRED)
    if(SODIUM_FOUND)
        include_directories(${SODIUM_INCLUDE_DIR})
        list(APPEND LIBS_OUTSIDE ${SODIUM_LIBRARY})
    endif()

    # Find and include mbedTLS package
    find_package(mbedTLS REQUIRED)
    if(MBEDTLS_FOUND)
        include_directories(${MBEDTLS_INCLUDE_DIRS})
        list(APPEND LIBS_OUTSIDE ${MBEDTLS_LIBRARIES})
    endif()
else()
    # Non-Apple platforms
    list(APPEND LIBS_OUTSIDE ${LIBSODIUM_LIB} ${MBEDTLS_LIBS})
endif()

# Add sources and make executable "e3db" (or "e3db.exe")
add_executable(e3db ${EXE_SOURCES} ${EXE_HEADERS})

# Specify the default library directory
set(DEFAULT_LIBRARY_DIR /usr/local/opt/mbedtls/lib)

# Check if a specific file exists
file(GLOB LIBRARY_SPECIAL_CHECK /opt/homebrew/Cellar/mbedtls/3.5.1/lib/libmbedtls.a)
if(LIBRARY_SPECIAL_CHECK)
   # Target-specific libraries for the other computer
    target_link_libraries(e3db e3db_lib ${LIBS_OUTSIDE}
                          /opt/homebrew/Cellar/mbedtls/3.5.1/lib/libmbedtls.a
                          /opt/homebrew/Cellar/mbedtls/3.5.1/lib/libmbedcrypto.a
                          /opt/homebrew/Cellar/mbedtls/3.5.1/lib/libmbedx509.a)
    
    # Target-specific library search path for the other computer
    link_directories(/opt/homebrew/Cellar/mbedtls/3.5.1/lib)
else()
    # Default libraries and library search path
    target_link_libraries(e3db e3db_lib ${LIBS_OUTSIDE})
    
    # Default library search path
    link_directories(${DEFAULT_LIBRARY_DIR})
endif()
