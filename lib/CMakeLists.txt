# CMake file for Tozny E3DB C-SDK Library

# Glob the source and header files
FILE(GLOB LIB_SOURCES *.c)
FILE(GLOB LIB_HEADERS *.h)

# Add sources and make static library "e3db_lib.a" (or "e3db_lib.lib")
ADD_LIBRARY(e3db_lib STATIC
            ${LIB_SOURCES}
            ${LIB_HEADERS})

target_link_libraries(e3db_lib ${LIBS_OUTSIDE})
