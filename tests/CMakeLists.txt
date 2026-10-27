# Unit tests using CTest
include_directories(BEFORE ${MBEDTLS_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR}/src)
include_directories(${PROJECT_BINARY_DIR}/src)
include_directories(${SODIUM_INCLUDE_DIRS})
include_directories(${PCRE2_INCLUDE_DIRS})
include_directories(${CARES_INCLUDE_DIRS})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(VALGRIND_EXECUTABLE NAMES valgrind)
endif()

# Some hosts (notably macOS, whose default soft limit is 256) start test
# processes with too few file descriptors for descriptor-heavy tests such as
# test_event_cpp. Raise the soft limit before exec'ing each test; a failure to
# raise it (hard limit too low) is ignored so the test still runs.
if(NOT WIN32)
    set(SS_TEST_LAUNCHER sh -c "ulimit -n 1024 2>/dev/null\; exec \"$0\" \"$@\"")
endif()

# "crypto.h" and friends come from the C reference implementation.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/reference)

# Helper function to add a unit test
function(ss_add_test name sources libs)
    if(WIN32 AND "${sources}" MATCHES "utils.cpp")
        list(APPEND sources ${PROJECT_SOURCE_DIR}/src/winsock.cpp)
    endif()
    add_executable(${name} ${sources})
    target_compile_definitions(${name} PRIVATE -DHAVE_CONFIG_H)
    target_link_libraries(${name} ${libs})
    if(WIN32)
        target_link_libraries(${name} ws2_32)
    endif()
    # Keep assertions enabled for tests even in Release builds.
    ss_project_options(${name})
    if(MSVC)
        target_compile_options(${name} PRIVATE /UNDEBUG)
    else()
        target_compile_options(${name} PRIVATE -UNDEBUG)
    endif()
    add_test(NAME ${name} COMMAND ${SS_TEST_LAUNCHER} $<TARGET_FILE:${name}>)
    set_tests_properties(${name} PROPERTIES LABELS "unit")

    if(VALGRIND_EXECUTABLE)
        add_test(NAME memcheck_${name}
            COMMAND ${SS_TEST_LAUNCHER} ${VALGRIND_EXECUTABLE}
                --tool=memcheck
                --leak-check=full
                --show-leak-kinds=definite,indirect
                --errors-for-leak-kinds=definite,indirect
                --error-exitcode=1
                --track-origins=yes
                --quiet
                $<TARGET_FILE:${name}>)
        set_tests_properties(memcheck_${name}
            PROPERTIES
                LABELS "memcheck"
                TIMEOUT 120)
    endif()
endfunction()

# C++ core (src/core): header-only ownership and allocation primitives.
foreach(core_test result pool buffer arena fixed_map ownership)
    ss_add_test(test_core_${core_test} "test_core_${core_test}.cpp" "")
    ss_strict_warnings(test_core_${core_test}.cpp)
endforeach()

# The embedding API on the static library (POSIX: the test uses BSD sockets).
if(TARGET shadowsocks-c-static AND UNIX)
    add_executable(test_local_api_cpp test_local_api_cpp.cpp)
    target_link_libraries(test_local_api_cpp PRIVATE shadowsocks-c-static Threads::Threads)
    target_compile_options(test_local_api_cpp PRIVATE -UNDEBUG)
    target_include_directories(test_local_api_cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    ss_project_options(test_local_api_cpp)
    ss_strict_warnings(test_local_api_cpp.cpp)
    add_test(NAME test_local_api_cpp COMMAND test_local_api_cpp)
    set_tests_properties(test_local_api_cpp PROPERTIES LABELS "unit" TIMEOUT 60)
endif()

# C++ event layer (src/event) over libuv.
ss_add_test(test_event_cpp "test_event_cpp.cpp" "ss_uv")
ss_strict_warnings(test_event_cpp.cpp)
set_tests_properties(test_event_cpp PROPERTIES TIMEOUT 30)

# test_heap_guard_cpp - library heaps fall back instead of failing a realloc
ss_add_test(test_heap_guard_cpp
    "test_heap_guard_cpp.cpp;${PROJECT_SOURCE_DIR}/src/core/heap_guard.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "ss_uv;ss_cares;ss_mbedcrypto;ss_sodium")
ss_strict_warnings(test_heap_guard_cpp.cpp)

# C++ sources under src/ must not allocate on the heap (see the script).
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME check_no_heap
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/check_no_heap.py --self-test)
    set_tests_properties(check_no_heap PROPERTIES LABELS "unit")

    # The programs and the static library must stay usable without a C++
    # runtime library (see docs/cpp-core.md). Sanitizer runtimes bring their
    # own C++ symbols, so skip the check there.
    set(SS_RUNTIME_CHECKED)
    foreach(target ss-local ss-server ss-tunnel ss-redir ss-manager shadowsocks-c-static)
        if(TARGET ${target})
            get_target_property(excluded ${target} EXCLUDE_FROM_ALL)
            if(NOT excluded)
                list(APPEND SS_RUNTIME_CHECKED $<TARGET_FILE:${target}>)
            endif()
        endif()
    endforeach()
    if(SS_RUNTIME_CHECKED AND CMAKE_NM AND NOT ENABLE_SANITIZERS)
        add_test(NAME check_cxx_runtime
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/check_cxx_runtime.py
                    --nm ${CMAKE_NM} ${SS_RUNTIME_CHECKED})
        set_tests_properties(check_cxx_runtime PROPERTIES LABELS "unit")
    endif()
endif()

# Shared-reference ownership and consuming pointer moves.
ss_add_test(test_ref "test_ref_cpp.cpp" "")

# test_base64 - no external deps
ss_add_test(test_base64
    "test_base64_cpp.cpp;${PROJECT_SOURCE_DIR}/src/base64.cpp"
    "")

# test_utils - needs sodium (for ss_malloc -> uses sodium in utils.cpp)
ss_add_test(test_utils
    "test_utils_cpp.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "ss_sodium")

# test_json - standalone json parser
ss_add_test(test_json
    "test_json_cpp.cpp;${PROJECT_SOURCE_DIR}/src/json.cpp"
    "${SS_MATH_LIBRARY}")

# test_ssurl - ss:// URI parsing (SIP002 and legacy)
ss_add_test(test_ssurl
    "test_ssurl_cpp.cpp;${PROJECT_SOURCE_DIR}/src/ssurl.cpp;${PROJECT_SOURCE_DIR}/src/base64.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "ss_sodium")

# test_netutils - address parsing and resolver integration
set(TEST_NETUTILS_LIBS
    ss_sodium
    ss_ev
    ss_cares
)
ss_add_test(test_netutils
    "test_netutils_cpp.cpp;${PROJECT_SOURCE_DIR}/src/netutils.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "${TEST_NETUTILS_LIBS}")

# test_cache - expiration uses a platform monotonic clock
ss_add_test(test_cache
    "test_cache_reference_cpp.cpp;${CMAKE_CURRENT_SOURCE_DIR}/reference/cache.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "ss_sodium")

# test_cache_cpp - fixed-capacity cache edge cases
ss_add_test(test_cache_cpp
    "test_cache_cpp.cpp;${CMAKE_CURRENT_SOURCE_DIR}/reference/cache.cpp"
    "ss_sodium")
ss_strict_warnings(test_cache_cpp.cpp ${CMAKE_CURRENT_SOURCE_DIR}/reference/cache.cpp)

# test_ppbloom - needs bloom
set(TEST_PPBLOOM_LIBS "")
list(APPEND TEST_PPBLOOM_LIBS bloom)
ss_add_test(test_ppbloom
    "test_ppbloom_cpp.cpp;${PROJECT_SOURCE_DIR}/src/ppbloom.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "${TEST_PPBLOOM_LIBS};ss_sodium;${SS_MATH_LIBRARY}")

if(SS_ENABLE_REGEX)
# test_rule - regex matching
set(TEST_RULE_LIBS
    ss_pcre2
    ss_sodium
)
ss_add_test(test_rule_cpp
    "test_rule_cpp.cpp;${PROJECT_SOURCE_DIR}/src/rule.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "${TEST_RULE_LIBS}")

# test_acl - ACL precedence and prefix matching
set(TEST_ACL_LIBS ${TEST_RULE_LIBS})
ss_add_test(test_acl
    "test_acl_cpp.cpp;${PROJECT_SOURCE_DIR}/src/acl.cpp;${PROJECT_SOURCE_DIR}/src/ipset.cpp;${PROJECT_SOURCE_DIR}/src/rule.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "${TEST_ACL_LIBS}")

endif()

# test_jconf - configuration parsing
set(TEST_JCONF_LIBS
    ss_sodium
    ss_ev
    ss_cares
)
ss_add_test(test_jconf
    "test_jconf_cpp.cpp;${PROJECT_SOURCE_DIR}/src/jconf.cpp;${PROJECT_SOURCE_DIR}/src/json.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp;${PROJECT_SOURCE_DIR}/src/netutils.cpp"
    "${TEST_JCONF_LIBS};${SS_MATH_LIBRARY}")

# The original C cipher implementation, kept under tests/reference as an
# independent oracle: the C++ codecs are tested against it byte for byte,
# and udp_session_eviction_client speaks to ss-server with it. The programs
# no longer contain it.
set(SS_CRYPTO_TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/reference/crypto.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/reference/aead.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/reference/aead2022.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/reference/aead2022_udp.cpp
    ${PROJECT_SOURCE_DIR}/src/ppbloom.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/reference/cache.cpp
    ${PROJECT_SOURCE_DIR}/src/base64.cpp
    ${PROJECT_SOURCE_DIR}/src/utils.cpp
)


# test_buffer - needs sodium and mbedtls for crypto.cpp buffer functions
ss_add_test(test_buffer
    "test_buffer_cpp.cpp;${SS_CRYPTO_TEST_SOURCES}"
    "ss_sodium;;ss_mbedcrypto;ss_ev;${TEST_PPBLOOM_LIBS};blake3;${SS_MATH_LIBRARY}")

# test_crypto - full crypto test
set(TEST_CRYPTO_LIBS
    ss_sodium

    ss_mbedcrypto
    ss_ev
)
list(APPEND TEST_CRYPTO_LIBS bloom)
# BLAKE3 backs the 2022 ciphers' key derivation
list(APPEND TEST_CRYPTO_LIBS blake3)
ss_add_test(test_crypto
    "test_crypto_cpp.cpp;${SS_CRYPTO_TEST_SOURCES}"
    "${TEST_CRYPTO_LIBS};${SS_MATH_LIBRARY}")

# test_aead2022 - Shadowsocks 2022 Edition (SIP022) ciphers
ss_add_test(test_aead2022
    "test_aead2022_cpp.cpp;${SS_CRYPTO_TEST_SOURCES}"
    "${TEST_CRYPTO_LIBS};${SS_MATH_LIBRARY}")

# test_crypto_aead_cpp - C++ AEAD codecs, differentially against aead.cpp
ss_add_test(test_crypto_aead_cpp
    "test_crypto_aead_cpp.cpp;${PROJECT_SOURCE_DIR}/src/crypto/aead.cpp;${PROJECT_SOURCE_DIR}/src/crypto/keys.cpp;${SS_CRYPTO_TEST_SOURCES}"
    "${TEST_CRYPTO_LIBS};${SS_MATH_LIBRARY}")
ss_strict_warnings(test_crypto_aead_cpp.cpp ${PROJECT_SOURCE_DIR}/src/crypto/aead.cpp)

# test_crypto_aead2022_cpp - C++ SIP022 codecs, differentially against aead2022.cpp
ss_add_test(test_crypto_aead2022_cpp
    "test_crypto_aead2022_cpp.cpp;${PROJECT_SOURCE_DIR}/src/crypto/aead2022.cpp;${PROJECT_SOURCE_DIR}/src/crypto/aead.cpp;${PROJECT_SOURCE_DIR}/src/crypto/keys.cpp;${SS_CRYPTO_TEST_SOURCES}"
    "${TEST_CRYPTO_LIBS};${SS_MATH_LIBRARY}")
ss_strict_warnings(test_crypto_aead2022_cpp.cpp ${PROJECT_SOURCE_DIR}/src/crypto/aead2022.cpp)


# test_interop_rust - interoperability against shadowsocks-rust.
# Skips itself when shadowsocks-rust or the built binaries are absent.
add_test(NAME test_interop_rust
    COMMAND bash "${PROJECT_SOURCE_DIR}/tests/test_interop_rust.sh"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
set_tests_properties(test_interop_rust PROPERTIES
    LABELS "integration"
    TIMEOUT 300
    SKIP_RETURN_CODE 77
    ENVIRONMENT "SS_BIN_DIR=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

# test_ss_setup - bash unit tests for the ss-setup TUI tool
add_test(NAME test_ss_setup
    COMMAND bash "${PROJECT_SOURCE_DIR}/tests/test_ss_setup.sh"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
set_tests_properties(test_ss_setup PROPERTIES LABELS "integration")

ss_add_test(test_ipset
    "test_ipset_cpp.cpp;${PROJECT_SOURCE_DIR}/src/ipset.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "ss_sodium")

ss_add_test(test_process
    "test_process_cpp.cpp;${PROJECT_SOURCE_DIR}/src/process.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "ss_sodium")
set_tests_properties(test_process PROPERTIES TIMEOUT 20)

if(UNIX)
    # The resolver against a delayed local DNS server.
    ss_add_test(test_resolver_cpp
        "test_resolver_cpp.cpp;${PROJECT_SOURCE_DIR}/src/relay/resolver.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
        "ss_ev;ss_cares;ss_sodium")
    ss_strict_warnings(test_resolver_cpp.cpp)
    set_tests_properties(test_resolver_cpp PROPERTIES TIMEOUT 30)
endif()

set(TEST_LITERAL_LIBS ss_sodium)
if(SS_ENABLE_REGEX)
    list(APPEND TEST_LITERAL_LIBS ss_pcre2)
endif()
ss_add_test(test_acl_literal
    "test_acl_literal_cpp.cpp;${PROJECT_SOURCE_DIR}/src/acl.cpp;${PROJECT_SOURCE_DIR}/src/ipset.cpp;${PROJECT_SOURCE_DIR}/src/rule.cpp;${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "${TEST_LITERAL_LIBS}")

# Tests ported from C build with the full C++ warning set. test_ipset_reference
# is intentionally absent: it needs the pre-migration libipset archives.
ss_strict_warnings(
    test_acl_cpp.cpp test_acl_literal_cpp.cpp test_aead2022_cpp.cpp test_base64_cpp.cpp
    test_buffer_cpp.cpp test_cache_reference_cpp.cpp test_crypto_cpp.cpp test_ipset_cpp.cpp
    test_jconf_cpp.cpp test_json_cpp.cpp test_netutils_cpp.cpp test_ppbloom_cpp.cpp test_process_cpp.cpp
    test_ref_cpp.cpp test_ssurl_cpp.cpp test_utils_cpp.cpp)


# Preloadable malloc counter for the allocation audit. It interposes the
# system allocator, so it is only built where that is supported (glibc,
# macOS) and never together with the sanitizers, which own malloc.
include(CheckSymbolExists)
check_symbol_exists(__GLIBC__ "stdlib.h" SS_HAVE_GLIBC)
if(SS_BUILD_EXECUTABLES AND NOT ENABLE_SANITIZERS AND (APPLE OR SS_HAVE_GLIBC))
    add_library(ss_alloc_audit SHARED alloc_audit/alloc_counter.c)
endif()

if(SS_BUILD_EXECUTABLES AND NOT CMAKE_CROSSCOMPILING)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME test_cli
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_cli.py
                    --bin-dir ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        set_tests_properties(test_cli PROPERTIES LABELS "integration" TIMEOUT 60)
        if(UNIX)
            add_executable(udp_session_eviction_client
                udp_session_eviction_client.c ${SS_CRYPTO_TEST_SOURCES})
            target_compile_definitions(udp_session_eviction_client PRIVATE HAVE_CONFIG_H)
            target_compile_options(udp_session_eviction_client PRIVATE -UNDEBUG)
            target_link_libraries(udp_session_eviction_client
                ${TEST_CRYPTO_LIBS} ${SS_MATH_LIBRARY})
            ss_project_options(udp_session_eviction_client)
            add_test(NAME test_udp_session_eviction
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_udp_session_eviction.py
                        --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
            set_tests_properties(test_udp_session_eviction PROPERTIES
                LABELS "integration" TIMEOUT 300)
            add_test(NAME test_experiment_supervisor
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/experiments/test_supervisor.py
                        --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
            set_tests_properties(test_experiment_supervisor PROPERTIES
                LABELS "integration" TIMEOUT 30)
            if(TARGET ss-manager)
                add_test(NAME test_manager
                    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_manager.py
                            --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
                set_tests_properties(test_manager PROPERTIES LABELS "integration" TIMEOUT 60)
            endif()
        endif()
        add_test(NAME test_experimental_transports
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/experiments/test_transport.py)
        set_tests_properties(test_experimental_transports PROPERTIES
            LABELS "integration" TIMEOUT 30)
        # Steady-state allocation audit (report-only until the C++ relay
        # lands; see tests/alloc_audit/measure_alloc.py).
        if(TARGET ss_alloc_audit)
            # The C++ codecs must not allocate once initialised.
            add_test(NAME alloc_steady_crypto_aead
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/alloc_audit/check_steady.py
                        --shim $<TARGET_FILE:ss_alloc_audit> -- $<TARGET_FILE:test_crypto_aead_cpp>)
            set_tests_properties(alloc_steady_crypto_aead PROPERTIES LABELS "unit" TIMEOUT 60)
            add_test(NAME alloc_steady_crypto_aead2022
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/alloc_audit/check_steady.py
                        --shim $<TARGET_FILE:ss_alloc_audit> -- $<TARGET_FILE:test_crypto_aead2022_cpp>)
            set_tests_properties(alloc_steady_crypto_aead2022 PROPERTIES LABELS "unit" TIMEOUT 60)
            add_test(NAME alloc_steady_cache
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/alloc_audit/check_steady.py
                        --shim $<TARGET_FILE:ss_alloc_audit> -- $<TARGET_FILE:test_cache_cpp>)
            set_tests_properties(alloc_steady_cache PROPERTIES LABELS "unit" TIMEOUT 60)
            # The programs: no heap allocation per relayed connection once
            # started, by name (DNS through the bounded c-ares heap) and by
            # address, for each cipher family.
            set(SS_ALLOC_CASES "aes-256-gcm@localhost" "2022-blake3-aes-256-gcm@127.0.0.1"
                               "chacha20-ietf-poly1305@127.0.0.1")
            foreach(case ${SS_ALLOC_CASES})
                string(REPLACE "@" ";" parts "${case}")
                list(GET parts 0 method)
                list(GET parts 1 target)
                add_test(NAME alloc_steady_programs_${method}
                    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/alloc_audit/measure_alloc.py
                            --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
                            --shim $<TARGET_FILE:ss_alloc_audit>
                            --method ${method} --target ${target} --max-per-connection 0)
                set_tests_properties(alloc_steady_programs_${method} PROPERTIES LABELS "integration" TIMEOUT 120)
            endforeach()
            foreach(method aes-256-gcm 2022-blake3-aes-256-gcm)
                add_test(NAME alloc_steady_programs_udp_${method}
                    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/alloc_audit/measure_alloc.py
                            --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
                            --shim $<TARGET_FILE:ss_alloc_audit>
                            --method ${method} --udp --warmup 20 --connections 50 --max-per-connection 0)
                set_tests_properties(alloc_steady_programs_udp_${method} PROPERTIES LABELS "integration" TIMEOUT 120)
            endforeach()
        endif()
        add_test(NAME test_printable_salt_interop
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/interop.py
                    --self --printable-salt --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        set_tests_properties(test_printable_salt_interop PROPERTIES
            LABELS "integration" TIMEOUT 90)
        # ss-tunnel through the C relay engine against ss-server (and
        # shadowsocks-rust when installed), every method.
        set(SS_TUNNEL_INTEROP_ARGS --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        add_test(NAME test_limits
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_limits.py
                    --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        set_tests_properties(test_limits PROPERTIES LABELS "integration" TIMEOUT 60)
        add_test(NAME test_server_acl
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_server_acl.py
                    --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        set_tests_properties(test_server_acl PROPERTIES LABELS "integration" TIMEOUT 90)
        add_test(NAME test_half_close
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_half_close.py
                    --bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        set_tests_properties(test_half_close PROPERTIES LABELS "integration" TIMEOUT 90)
        add_test(NAME test_tunnel_interop
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tunnel_interop.py ${SS_TUNNEL_INTEROP_ARGS})
        set_tests_properties(test_tunnel_interop PROPERTIES LABELS "integration" TIMEOUT 300)
    endif()
endif()

# The zero-allocation checks hold for the bundled Mbed TLS, which is built
# with MBEDTLS_BLOCK_CIPHER_C; a system Mbed TLS may allocate during GCM key
# setup. Keep those tests visible but disabled in system-dependency builds.
if(NOT SS_DEPENDENCY_MODE STREQUAL "bundled")
    get_property(ss_all_tests DIRECTORY PROPERTY TESTS)
    foreach(ss_test IN LISTS ss_all_tests)
        if(ss_test MATCHES "^alloc_steady_(crypto|programs)")
            set_tests_properties(${ss_test} PROPERTIES DISABLED TRUE)
        endif()
    endforeach()
endif()
