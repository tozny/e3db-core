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
    find_package(mbedTLS REQUIRED)
    
    # Check if Sodium and mbedTLS are found
    if(SODIUM_FOUND AND MBEDTLS_FOUND)
        # Include directories
        include_directories(${SODIUM_INCLUDE_DIR} ${MBEDTLS_INCLUDE_DIRS})

        # Add libraries to the list
        set(LIBS_OUTSIDE ${LIBS_OUTSIDE} ${SODIUM_LIBRARY} ${MBEDTLS_LIBRARIES})
    endif()
else()
    # Non-Apple platforms
    set(LIBS_OUTSIDE ${LIBS_OUTSIDE} sodium mbedtls)
endif()

# Add sources and make executable "simple" (or "simple.exe")
add_executable(simple ${EXE_SOURCES} ${EXE_HEADERS})

# Static link the SDK library and external libraries
target_link_libraries(simple e3db_lib ${LIBS_OUTSIDE}
                      /usr/local/opt/mbedtls/lib/libmbedtls.a
                      /usr/local/opt/mbedtls/lib/libmbedcrypto.a
                      /usr/local/opt/mbedtls/lib/libmbedx509.a)

# Add the library search path if needed
link_directories(/usr/local/opt/mbedtls/lib)
