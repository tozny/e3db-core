# CMake file for Tozny E3DB C-SDK Library

# Glob the source and header files
FILE(GLOB LIB_SOUCES *.c)
FILE(GLOB LIB_HEADERS *.h)

# Add sources and make static library "e3db_lib.a" (or "e3db_lib.lib")
ADD_LIBRARY(e3db_lib STATIC
            ${LIB_SOUCES}
            ${LIB_HEADERS})
