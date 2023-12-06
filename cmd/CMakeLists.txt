# CMake file for Tozny E3DB C-SDK Command Line Interface

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

# Add sources and make executable "e3db" (or "e3db.exe")
add_executable(e3db
               ${EXE_SOURCES}
               ${EXE_HEADERS})

# Static link the SDK library and external libraries
target_link_libraries(e3db 
                      e3db_lib
                      ${LIBS_OUTSIDE})
