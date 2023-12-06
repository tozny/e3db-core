# CMake file for Tozny E3DB C-SDK Command Line Interface

# Glob the source and header files
file(GLOB EXE_SOURCES *.c)
file(GLOB EXE_HEADERS *.h)

# Set dependent 3rd-party library linkages
set(LIBS_OUTSIDE curl m)

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
    list(APPEND LIBS_OUTSIDE sodium mbedtls)
endif()

# Add sources and make executable "e3db" (or "e3db.exe")
add_executable(e3db ${EXE_SOURCES} ${EXE_HEADERS})

# Static link the SDK library and external libraries
target_link_libraries(e3db e3db_lib ${LIBS_OUTSIDE}
                      /usr/local/opt/mbedtls/lib/libmbedtls.a
                      /usr/local/opt/mbedtls/lib/libmbedcrypto.a
                      /usr/local/opt/mbedtls/lib/libmbedx509.a)

# Add the library search path if needed
link_directories(/usr/local/opt/mbedtls/lib)
