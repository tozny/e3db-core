# CMake file for Tozny E3DB C-SDK Simple Example

# Glob the source and header files
FILE(GLOB EXE_SOUCES *.c)
FILE(GLOB EXE_HEADERS *.h)

# Set dependent 3rd-party library linkages
# TODO this may change for if not using Linux
SET(LIBS_OUTSIDE
    curl ssl crypto m sodium)

# Add sources and make executable "simple" (or "simple.exe")
add_executable(simple
               ${EXE_SOUCES}
               ${EXE_HEADERS})

# Static link the SDK library
target_link_libraries(simple 
                      e3db_lib
                      ${LIBS_OUTSIDE})