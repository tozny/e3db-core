# CMake file for Tozny E3DB C-SDK Simple Example

# Glob the source and header files
FILE(GLOB EXE_SOURCES *.c)
FILE(GLOB EXE_HEADERS *.h)

# Set dependent 3rd-party library linkages
SET(LIBS_OUTSIDE curl m)

# Check if the platform is macOS (Darwin)
if(APPLE)
    # Find Sodium package
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
# Add sources and make executable "simple" (or "simple.exe")
add_executable(simple
               ${EXE_SOURCES}
               ${EXE_HEADERS})

# Static link the SDK library
target_link_libraries(simple 
                      e3db_lib
                      ${LIBS_OUTSIDE})
