# FindSodium.cmake - Find libsodium with version check
#
# Sets:
#   SODIUM_FOUND
#   SODIUM_INCLUDE_DIRS
#   SODIUM_LIBRARIES

find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    HINTS
        /opt/homebrew/include
        /usr/local/include
        /usr/local/opt/libsodium/include
        /opt/homebrew/opt/libsodium/include
        /usr/include
        $ENV{LIBSODIUM_INCLUDE_DIR}
        $ENV{LIBSODIUM_DIR}/include
)

find_library(SODIUM_LIBRARY
    NAMES sodium
    HINTS
        /opt/homebrew/lib
        /usr/local/lib
        /usr/local/opt/libsodium/lib
        /opt/homebrew/opt/libsodium/lib
        /usr/lib
)

if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
    set(SODIUM_FOUND TRUE)
    set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
    set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})

    # Version check: require SODIUM_LIBRARY_VERSION_MAJOR >= 7 (libsodium >= 1.0.4)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_INCLUDES ${SODIUM_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${SODIUM_LIBRARY})
    check_c_source_compiles("
        #include <sodium.h>
        #if SODIUM_LIBRARY_VERSION_MAJOR < 7
        #error libsodium too old
        #endif
        int main(void) { return 0; }
    " SODIUM_VERSION_OK)
    unset(CMAKE_REQUIRED_INCLUDES)
    unset(CMAKE_REQUIRED_LIBRARIES)

    if(NOT SODIUM_VERSION_OK)
        message(FATAL_ERROR "libsodium found but version is too old. Require >= 1.0.4 (SODIUM_LIBRARY_VERSION_MAJOR >= 7)")
    endif()

    message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
else()
    set(SODIUM_FOUND FALSE)
    message(FATAL_ERROR "Could not find libsodium. Install libsodium-dev or equivalent.")
endif()

# CMake find_dependency uses the exact package-name spelling.
set(Sodium_FOUND ${SODIUM_FOUND})
