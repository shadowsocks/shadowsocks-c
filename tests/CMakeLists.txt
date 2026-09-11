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

# Helper function to add a unit test
function(ss_add_test name sources libs)
    if(WIN32 AND "${sources}" MATCHES "utils.c")
        list(APPEND sources ${PROJECT_SOURCE_DIR}/src/winsock.c)
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
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "unit")

    if(VALGRIND_EXECUTABLE)
        add_test(NAME memcheck_${name}
            COMMAND ${VALGRIND_EXECUTABLE}
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

# test_base64 - no external deps
ss_add_test(test_base64
    "test_base64.c;${PROJECT_SOURCE_DIR}/src/base64.c"
    "")

# test_utils - needs sodium (for ss_malloc -> uses sodium in utils.c)
ss_add_test(test_utils
    "test_utils.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "ss_sodium")

# test_json - standalone json parser
ss_add_test(test_json
    "test_json.c;${PROJECT_SOURCE_DIR}/src/json.c"
    "${SS_MATH_LIBRARY}")

# test_ssurl - ss:// URI parsing (SIP002 and legacy)
ss_add_test(test_ssurl
    "test_ssurl.c;${PROJECT_SOURCE_DIR}/src/ssurl.c;${PROJECT_SOURCE_DIR}/src/base64.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "ss_sodium")

# test_netutils - address parsing and resolver integration
set(TEST_NETUTILS_LIBS
    ss_sodium
    ss_ev
    ss_cares
)
ss_add_test(test_netutils
    "test_netutils.c;${PROJECT_SOURCE_DIR}/src/netutils.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_NETUTILS_LIBS}")

# test_cache - expiration uses a platform monotonic clock
ss_add_test(test_cache
    "test_cache.c;${PROJECT_SOURCE_DIR}/src/cache.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "ss_sodium")

# test_ppbloom - needs bloom
set(TEST_PPBLOOM_LIBS "")
list(APPEND TEST_PPBLOOM_LIBS bloom)
ss_add_test(test_ppbloom
    "test_ppbloom.c;${PROJECT_SOURCE_DIR}/src/ppbloom.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_PPBLOOM_LIBS};ss_sodium;${SS_MATH_LIBRARY}")

if(SS_ENABLE_REGEX)
# test_rule - regex matching
set(TEST_RULE_LIBS
    ss_pcre2
    ss_sodium
)
ss_add_test(test_rule
    "test_rule.c;${PROJECT_SOURCE_DIR}/src/rule.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_RULE_LIBS}")

# test_acl - ACL precedence and prefix matching
set(TEST_ACL_LIBS ${TEST_RULE_LIBS})
ss_add_test(test_acl
    "test_acl.c;${PROJECT_SOURCE_DIR}/src/acl.c;${PROJECT_SOURCE_DIR}/src/ipset.c;${PROJECT_SOURCE_DIR}/src/rule.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_ACL_LIBS}")

endif()

# test_jconf - configuration parsing
set(TEST_JCONF_LIBS
    ss_sodium
    ss_ev
    ss_cares
)
ss_add_test(test_jconf
    "test_jconf.c;${PROJECT_SOURCE_DIR}/src/jconf.c;${PROJECT_SOURCE_DIR}/src/json.c;${PROJECT_SOURCE_DIR}/src/utils.c;${PROJECT_SOURCE_DIR}/src/netutils.c"
    "${TEST_JCONF_LIBS};${SS_MATH_LIBRARY}")

# Crypto sources shared by the tests that link the crypto layer. The AEAD-2022
# ciphers pull in BLAKE3 (linked as the `blake3` target) and the session-based
# UDP codec, so they must be built together with crypto.c.
set(SS_CRYPTO_TEST_SOURCES
    ${PROJECT_SOURCE_DIR}/src/crypto.c
    ${PROJECT_SOURCE_DIR}/src/aead.c
    ${PROJECT_SOURCE_DIR}/src/aead2022.c
    ${PROJECT_SOURCE_DIR}/src/aead2022_udp.c
    ${PROJECT_SOURCE_DIR}/src/ppbloom.c
    ${PROJECT_SOURCE_DIR}/src/cache.c
    ${PROJECT_SOURCE_DIR}/src/base64.c
    ${PROJECT_SOURCE_DIR}/src/utils.c
)

if(SS_ENABLE_LEGACY)
    list(APPEND SS_CRYPTO_TEST_SOURCES ${PROJECT_SOURCE_DIR}/src/stream.c)
endif()

# test_buffer - needs sodium and mbedtls for crypto.c buffer functions
ss_add_test(test_buffer
    "test_buffer.c;${SS_CRYPTO_TEST_SOURCES}"
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
    "test_crypto.c;${SS_CRYPTO_TEST_SOURCES}"
    "${TEST_CRYPTO_LIBS};${SS_MATH_LIBRARY}")

# test_aead2022 - Shadowsocks 2022 Edition (SIP022) ciphers
ss_add_test(test_aead2022
    "test_aead2022.c;${SS_CRYPTO_TEST_SOURCES}"
    "${TEST_CRYPTO_LIBS};${SS_MATH_LIBRARY}")

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
    "test_ipset.c;${PROJECT_SOURCE_DIR}/src/ipset.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "ss_sodium")

ss_add_test(test_process
    "test_process.c;${PROJECT_SOURCE_DIR}/src/process.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "ss_sodium")
set_tests_properties(test_process PROPERTIES TIMEOUT 20)

ss_add_test(test_resolv
    "test_resolv.c;${PROJECT_SOURCE_DIR}/src/resolv.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "ss_ev;ss_cares;ss_sodium")
set_tests_properties(test_resolv PROPERTIES TIMEOUT 20)

set(TEST_LITERAL_LIBS ss_sodium)
if(SS_ENABLE_REGEX)
    list(APPEND TEST_LITERAL_LIBS ss_pcre2)
endif()
ss_add_test(test_acl_literal
    "test_acl_literal.c;${PROJECT_SOURCE_DIR}/src/acl.c;${PROJECT_SOURCE_DIR}/src/ipset.c;${PROJECT_SOURCE_DIR}/src/rule.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_LITERAL_LIBS}")

ss_add_test(test_event "test_event.c" "ss_ev")
set_tests_properties(test_event PROPERTIES TIMEOUT 30)
ss_add_test(test_resolv_async
    "test_resolv_async.c;${PROJECT_SOURCE_DIR}/src/resolv.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "ss_ev;ss_cares;ss_sodium")
set_tests_properties(test_resolv_async PROPERTIES TIMEOUT 30)
