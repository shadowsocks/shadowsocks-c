# FindCares.cmake - Find c-ares library
#
# Sets:
#   CARES_FOUND
#   CARES_INCLUDE_DIRS
#   CARES_LIBRARIES

find_path(CARES_INCLUDE_DIR
    NAMES ares.h
    HINTS
        /opt/homebrew/include
        /usr/local/include
        /opt/homebrew/opt/c-ares/include
        /usr/local/opt/c-ares/include
        /usr/include
)

find_library(CARES_LIBRARY
    NAMES cares
    HINTS
        /opt/homebrew/lib
        /usr/local/lib
        /opt/homebrew/opt/c-ares/lib
        /usr/local/opt/c-ares/lib
        /usr/lib
)

if(CARES_INCLUDE_DIR AND CARES_LIBRARY)
    set(CARES_FOUND TRUE)
    set(CARES_INCLUDE_DIRS ${CARES_INCLUDE_DIR})
    set(CARES_LIBRARIES ${CARES_LIBRARY})

    # Verify ares_library_init exists
    include(CheckLibraryExists)
    check_library_exists(cares ares_library_init "" CARES_HAS_INIT)
    if(NOT CARES_HAS_INIT)
        message(WARNING "c-ares found but ares_library_init not detected. Proceeding anyway.")
    endif()

    message(STATUS "Found c-ares: ${CARES_LIBRARY}")
else()
    set(CARES_FOUND FALSE)
    message(FATAL_ERROR "Could not find c-ares library. Install libc-ares-dev or equivalent.")
endif()

# CMake find_dependency uses the exact package-name spelling.
set(Cares_FOUND ${CARES_FOUND})
