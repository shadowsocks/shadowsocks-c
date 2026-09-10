# FindMbedTLS.cmake - Find mbedTLS library with feature detection
#
# Sets:
#   MBEDTLS_FOUND
#   MBEDTLS_INCLUDE_DIRS
#   MBEDTLS_CRYPTO_LIBRARY
#   MBEDTLS_TLS_LIBRARY
#
# The headers and the libraries MUST come from the same installation. Mixing
# them is not a build-time error but a memory-corruption bug at runtime:
# mbedTLS structs such as mbedtls_cipher_context_t changed size between 3.x
# and 4.x, so a context allocated with sizeof() from one version and
# initialized by the other overruns its heap block. Homebrew makes this easy
# to hit, since mbedtls (4.x) and the keg-only mbedtls@3 can both be present
# and CMAKE_PREFIX_PATH outranks HINTS in find_library's search order.

include(CheckCSourceCompiles)

# This codebase targets the mbedTLS 3.x API, so prefer a 3.x installation.
set(_MBEDTLS_PREFIX_HINTS
    ${MbedTLS_ROOT}
    ${CMAKE_PREFIX_PATH}
    /opt/homebrew/opt/mbedtls@3
    /usr/local/opt/mbedtls@3
    /opt/homebrew/opt/mbedtls
    /usr/local/opt/mbedtls
    /opt/homebrew
    /usr/local
    /usr
)

# Locate a prefix that provides both the headers and libmbedcrypto, so the
# two can never be drawn from different installations.
if(NOT CMAKE_CROSSCOMPILING)
foreach(_prefix IN LISTS _MBEDTLS_PREFIX_HINTS)
    if(EXISTS "${_prefix}/include/mbedtls/cipher.h")
        find_library(_MBEDTLS_CRYPTO_IN_PREFIX
            NAMES mbedcrypto
            PATHS "${_prefix}/lib" "${_prefix}/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
            NO_DEFAULT_PATH
        )
        if(_MBEDTLS_CRYPTO_IN_PREFIX)
            set(_MBEDTLS_ROOT "${_prefix}")
            break()
        endif()
        unset(_MBEDTLS_CRYPTO_IN_PREFIX CACHE)
    endif()
endforeach()
endif()

if(_MBEDTLS_ROOT)
    # Pin every component to the prefix chosen above.
    find_path(MBEDTLS_INCLUDE_DIR
        NAMES mbedtls/cipher.h
        PATHS "${_MBEDTLS_ROOT}/include"
        NO_DEFAULT_PATH
    )
    find_library(MBEDTLS_CRYPTO_LIBRARY
        NAMES mbedcrypto
        PATHS "${_MBEDTLS_ROOT}/lib" "${_MBEDTLS_ROOT}/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
        NO_DEFAULT_PATH
    )
    find_library(MBEDTLS_TLS_LIBRARY
        NAMES mbedtls
        PATHS "${_MBEDTLS_ROOT}/lib" "${_MBEDTLS_ROOT}/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
        NO_DEFAULT_PATH
    )
else()
    # No single prefix provided both; fall back to a plain search.
    find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/cipher.h)
    find_library(MBEDTLS_CRYPTO_LIBRARY NAMES mbedcrypto)
    find_library(MBEDTLS_TLS_LIBRARY NAMES mbedtls)
endif()

unset(_MBEDTLS_CRYPTO_IN_PREFIX CACHE)

if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_CRYPTO_LIBRARY)
    set(MBEDTLS_FOUND TRUE)
    set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})

    set(_mbedtls_version_header "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")
    if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")
        set(_mbedtls_version_header "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")
    endif()
    file(STRINGS "${_mbedtls_version_header}" _mbedtls_version_line
        REGEX "^#define MBEDTLS_VERSION_STRING +\"[0-9.]+\"")
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" MBEDTLS_VERSION "${_mbedtls_version_line}")
    if(NOT MBEDTLS_VERSION OR MBEDTLS_VERSION VERSION_LESS 2 OR NOT MBEDTLS_VERSION VERSION_LESS 4)
        message(FATAL_ERROR "Supported system Mbed TLS versions are 2.x and 3.x; found ${MBEDTLS_VERSION}")
    endif()

    set(CMAKE_REQUIRED_INCLUDES ${MBEDTLS_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${MBEDTLS_CRYPTO_LIBRARY})

    # Check for required CFB mode support
    check_c_source_compiles("
        #include <mbedtls/cipher.h>
        #if !defined(MBEDTLS_CIPHER_MODE_CFB)
        #error CFB mode not supported
        #endif
        int main(void) { return 0; }
    " MBEDTLS_HAS_CFB)

    if(NOT MBEDTLS_HAS_CFB)
        # Try mbedtls 3.x config path
        check_c_source_compiles("
            #include <mbedtls/build_info.h>
            #include <mbedtls/cipher.h>
            #if !defined(MBEDTLS_CIPHER_MODE_CFB)
            #error CFB mode not supported
            #endif
            int main(void) { return 0; }
        " MBEDTLS_HAS_CFB_V3)

        if(NOT MBEDTLS_HAS_CFB_V3)
            message(FATAL_ERROR "mbedTLS found but MBEDTLS_CIPHER_MODE_CFB is not enabled. "
                "Please enable CFB mode in your mbedTLS configuration.")
        endif()
    endif()

    # Verify the headers and the runtime library agree on the version. A
    # mismatch silently corrupts the heap, so refuse to configure instead.
    if(NOT CMAKE_CROSSCOMPILING AND NOT DEFINED MBEDTLS_VERSION_CONSISTENT)
        try_run(_mbedtls_run_result _mbedtls_compile_result
            ${CMAKE_BINARY_DIR}/CMakeFiles/mbedtls_version_check
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls_version_check.c
            CMAKE_FLAGS
                "-DINCLUDE_DIRECTORIES=${MBEDTLS_INCLUDE_DIR}"
                "-DLINK_LIBRARIES=${MBEDTLS_CRYPTO_LIBRARY}"
            RUN_OUTPUT_VARIABLE _mbedtls_run_output
        )
        if(_mbedtls_compile_result AND _mbedtls_run_result EQUAL 0)
            set(MBEDTLS_VERSION_CONSISTENT TRUE CACHE INTERNAL "")
        elseif(_mbedtls_compile_result)
            message(FATAL_ERROR
                "mbedTLS headers and library are from different installations:\n"
                "  ${_mbedtls_run_output}\n"
                "  headers: ${MBEDTLS_INCLUDE_DIR}\n"
                "  library: ${MBEDTLS_CRYPTO_LIBRARY}\n"
                "Mixing them corrupts memory at runtime. Point both at the same "
                "mbedTLS installation, e.g. "
                "-DCMAKE_PREFIX_PATH=/opt/homebrew/opt/mbedtls@3")
        endif()
    endif()

    unset(CMAKE_REQUIRED_INCLUDES)
    unset(CMAKE_REQUIRED_LIBRARIES)

    message(STATUS "Found mbedTLS: ${MBEDTLS_CRYPTO_LIBRARY}")
else()
    set(MBEDTLS_FOUND FALSE)
    message(FATAL_ERROR "Could not find mbedTLS library. Install libmbedtls-dev or equivalent.")
endif()

# CMake find_dependency uses the exact package-name spelling.
set(MbedTLS_FOUND ${MBEDTLS_FOUND})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
    REQUIRED_VARS MBEDTLS_INCLUDE_DIR MBEDTLS_CRYPTO_LIBRARY
    VERSION_VAR MBEDTLS_VERSION)
