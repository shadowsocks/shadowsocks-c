cmake_minimum_required(VERSION 3.20)

set(PROJECT_NAME shadowsocks-c)
set(RELEASE_DATE 2026-02-09)
set(PROJECT_VERSION "3.3.6")
set(PROJECT_DESC "a lightweight secured socks5 proxy")
set(PROJECT_URL "https://shadowsocks.org")
set(PROJECT_ISSUES_URL "https://github.com/shadowsocks/shadowsocks-libev")
project(${PROJECT_NAME} VERSION ${PROJECT_VERSION} LANGUAGES C)
if(MSVC)
    message(FATAL_ERROR "MSVC is not supported yet. Use MinGW-w64 (UCRT64) or the Zig Windows toolchain; see docs/modernization.md.")
endif()

include(GNUInstallDirs)
include(CTest)

# Compilation database for clang-tidy and other tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C11 with GNU extensions. _GNU_SOURCE stays for the glibc-specific
# interfaces used by the Linux-only modules (ss-redir, connmark/nftables).
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

option(ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ENABLE_COVERAGE "Build with coverage instrumentation" OFF)
option(SS_WARNINGS_AS_ERRORS "Treat project warnings as errors" ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

set(CMAKE_MACOSX_RPATH TRUE)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build configuration" FORCE)
endif ()
# Detect linux
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(LINUX TRUE)
endif ()

message(STATUS "Running cmake version ${CMAKE_VERSION}")

option(WITH_STATIC "Link executable dependencies statically" ON)
option(SS_BUILD_EXECUTABLES "Build command-line programs" ON)
option(SS_BUILD_STATIC_LIBRARY "Build the static embedding library" ON)
option(SS_BUILD_SHARED_LIBRARY "Build the shared embedding library" ON)
option(SS_INSTALL_TOOLS "Install platform shell tools" OFF)
option(ENABLE_CONNMARKTOS "Enable saved connmark to IP TOS QoS feature" OFF)
option(ENABLE_NFTABLES "Report malicious IP to nftables" OFF)

option(SS_MINIMAL "Disable regex, plugins, manager and legacy stream ciphers" OFF)
option(SS_ENABLE_REGEX "Enable PCRE2 ACL patterns" ON)
option(SS_ENABLE_PLUGINS "Enable SIP003 and obfsproxy subprocesses" ON)
option(SS_ENABLE_LEGACY "Enable legacy stream ciphers" ON)
if(SS_MINIMAL)
    set(SS_ENABLE_REGEX OFF)
    set(SS_ENABLE_PLUGINS OFF)
    set(SS_ENABLE_LEGACY OFF)
    set(WITH_SS_MANAGER OFF)
endif()
include(cmake/Dependencies.cmake)

# Connmarktos support
if(ENABLE_CONNMARKTOS)
    if(NOT LINUX)
        message(FATAL_ERROR "connmarktos is only supported on Linux")
    endif()
    find_library(NETFILTER_CONNTRACK_LIB netfilter_conntrack)
    find_library(NFNETLINK_LIB nfnetlink)
    if(NOT NETFILTER_CONNTRACK_LIB)
        message(FATAL_ERROR "--enable-connmarktos specified but libnetfilter_conntrack not found")
    endif()
    set(USE_NFCONNTRACK_TOS 1)
    message(STATUS "Connmarktos enabled")
endif()

# Nftables support
if(ENABLE_NFTABLES)
    if(NOT LINUX)
        message(FATAL_ERROR "nftables is only supported on Linux")
    endif()
    find_library(MNL_LIB mnl)
    find_library(NFTNL_LIB nftnl)
    if(NOT MNL_LIB OR NOT NFTNL_LIB)
        message(FATAL_ERROR "--enable-nftables specified but libmnl or libnftnl not found")
    endif()
    set(USE_NFTABLES 1)
    message(STATUS "Nftables enabled")
endif()

# Run platform tests
include(${PROJECT_SOURCE_DIR}/cmake/configure.cmake)
configure_file(${PROJECT_SOURCE_DIR}/cmake/config.h.cmake ${PROJECT_BINARY_DIR}/src/config.h)
include(cmake/ProjectOptions.cmake)
ss_project_options(ss_ev)
include_directories(${PROJECT_BINARY_DIR}/src)
add_compile_definitions(HAVE_CONFIG_H)

set(LIBBLOOM_SOURCE
        third_party/bloom/bloom.c
        third_party/bloom/murmur2/MurmurHash2.c
        )

add_library(bloom STATIC ${LIBBLOOM_SOURCE})
target_include_directories(bloom PUBLIC third_party/bloom third_party/bloom/murmur2)

add_subdirectory(src)
include(cmake/InstallPackage.cmake)
add_subdirectory(doc)

# Testing
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# Coverage report (requires ENABLE_COVERAGE=ON, lcov and genhtml)
# Usage: make coverage (after running ctest / integration tests)
if (ENABLE_COVERAGE)
    find_program(LCOV_EXECUTABLE lcov)
    find_program(GENHTML_EXECUTABLE genhtml)
    if (LCOV_EXECUTABLE AND GENHTML_EXECUTABLE)
        add_custom_target(coverage
                COMMAND ${LCOV_EXECUTABLE} --capture --directory ${PROJECT_BINARY_DIR}
                        --output-file ${PROJECT_BINARY_DIR}/coverage.info
                        --include ${PROJECT_SOURCE_DIR}/src/*
                        --ignore-errors mismatch,unused,empty,gcov
                COMMAND ${LCOV_EXECUTABLE} --list ${PROJECT_BINARY_DIR}/coverage.info
                COMMAND ${GENHTML_EXECUTABLE} ${PROJECT_BINARY_DIR}/coverage.info
                        --output-directory ${PROJECT_BINARY_DIR}/coverage-html
                COMMAND ${CMAKE_COMMAND} -E echo "Coverage report: ${PROJECT_BINARY_DIR}/coverage-html/index.html"
                WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                VERBATIM
                )
    else ()
        message(WARNING "lcov/genhtml not found - 'coverage' target unavailable")
    endif ()
endif ()

# Install ss-nat on Linux
if(LINUX AND SS_INSTALL_TOOLS)
    install(PROGRAMS src/ss-nat DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# Install ss-setup TUI tool
if(UNIX AND SS_INSTALL_TOOLS)
    install(PROGRAMS scripts/ss-setup.sh DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME ss-setup)
endif()
