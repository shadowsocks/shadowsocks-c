# redir need linux/* stuff
if (LINUX)
    option(WITH_SS_REDIR "Build ss-redir" ON)
    option(WITH_SS_MANAGER "Build ss-manager" ON)
else ()
    option(WITH_SS_REDIR "Build ss-redir" OFF)
    option(WITH_SS_MANAGER "Build ss-manager" OFF)
endif ()


set(SS_ACL_SOURCE
        acl.c
        ipset.c
        rule.c
        )

set(SS_CRYPTO_SOURCE
        crypto.c
        aead.c
        aead2022.c
        aead2022_udp.c
        base64.c
        )

# BLAKE3 (vendored) provides the key derivation for the 2022 ciphers. Only
# the portable backend is built: the SIMD ones need per-file ISA flags and
# extra assembly, which is not worth it for key derivation.
add_library(blake3 STATIC
        blake3/blake3.c
        blake3/blake3_dispatch.c
        blake3/blake3_portable.c
        )
target_compile_definitions(blake3 PUBLIC
        BLAKE3_NO_AVX512 BLAKE3_NO_AVX2 BLAKE3_NO_SSE41 BLAKE3_NO_SSE2
        BLAKE3_USE_NEON=0
        )
target_include_directories(blake3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# vendored upstream code is not held to the project's -Werror budget
target_compile_options(blake3 PRIVATE -Wno-error -Wno-unused-function)
set_target_properties(blake3 PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(SS_ENABLE_LEGACY)
    list(APPEND SS_CRYPTO_SOURCE stream.c)
endif()
if(SS_ENABLE_PLUGINS)
    set(SS_PLUGIN_SOURCE plugin.c process.c)
else()
    set(SS_PLUGIN_SOURCE plugin_disabled.c)
endif()

set(SS_SHARED_SOURCES
        ppbloom.c
        utils.c
        jconf.c
        json.c
        netutils.c
        )
if (MINGW)
set(SS_SHARED_SOURCES ${SS_SHARED_SOURCES} winsock.c)
endif ()

set(LIBSHADOWSOCKS_LIBEV_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        cache.c
        local.c
        resolv.c
        ssurl.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        ${SS_ACL_SOURCE}
        )

set(SS_LOCAL_SOURCE
        ${LIBSHADOWSOCKS_LIBEV_SOURCE}

        )

set(SS_TUNNEL_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        cache.c
        tunnel.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        )

set(SS_SERVER_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        cache.c
        resolv.c
        server.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        ${SS_ACL_SOURCE}
        )

set(SS_MANAGER_SOURCE
        ${SS_SHARED_SOURCES}
        manager.c
        )

set(SS_REDIR_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        cache.c
        redir.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        )


set(SS_CORE_DEPS ss_ev ss_cares ss_sodium ss_mbedcrypto blake3 bloom Threads::Threads ${SS_MATH_LIBRARY})
set(SS_ACL_DEPS)
if(SS_ENABLE_REGEX)
    list(APPEND SS_ACL_DEPS ss_pcre2)
endif()
if(ENABLE_CONNMARKTOS)
    list(APPEND SS_SERVER_DEPS ${NETFILTER_CONNTRACK_LIB} ${NFNETLINK_LIB})
endif()
if(ENABLE_NFTABLES)
    list(APPEND SS_SERVER_DEPS ${MNL_LIB} ${NFTNL_LIB})
endif()

function(ss_program name module sources)
    add_executable(${name} ${sources})
    target_compile_definitions(${name} PRIVATE ${module})
    target_link_libraries(${name} PRIVATE ${SS_CORE_DEPS} ${ARGN})
    ss_project_options(${name})
    install(TARGETS ${name} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endfunction()

if(SS_BUILD_EXECUTABLES)
    ss_program(ss-local MODULE_LOCAL "${SS_LOCAL_SOURCE}" ${SS_ACL_DEPS})
    ss_program(ss-server MODULE_REMOTE "${SS_SERVER_SOURCE}" ${SS_ACL_DEPS} ${SS_SERVER_DEPS})
    ss_program(ss-tunnel MODULE_TUNNEL "${SS_TUNNEL_SOURCE}")
    if(WITH_SS_MANAGER)
        ss_program(ss-manager MODULE_MANAGER "${SS_MANAGER_SOURCE}")
    endif()
    if(WITH_SS_REDIR)
        if(NOT LINUX)
            message(FATAL_ERROR "ss-redir requires Linux")
        endif()
        ss_program(ss-redir MODULE_REDIR "${SS_REDIR_SOURCE}")
    endif()
endif()

foreach(kind STATIC SHARED)
    if(SS_BUILD_${kind}_LIBRARY)
        string(TOLOWER "${kind}" suffix)
        set(target shadowsocks-c-${suffix})
        add_library(${target} ${kind} ${LIBSHADOWSOCKS_LIBEV_SOURCE})
        add_library(shadowsocks-libev-${suffix} ALIAS ${target})
        target_compile_definitions(${target} PRIVATE MODULE_LOCAL LIB_ONLY)
        target_include_directories(${target} PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
        target_link_libraries(${target} PRIVATE ${SS_CORE_DEPS} ${SS_ACL_DEPS})
        set_target_properties(${target} PROPERTIES OUTPUT_NAME shadowsocks-c)
        if(kind STREQUAL "SHARED")
            set_target_properties(${target} PROPERTIES VERSION 2.0.0 SOVERSION 2)
        endif()
        ss_project_options(${target})
        install(TARGETS ${target}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endforeach()
if(SS_BUILD_STATIC_LIBRARY OR SS_BUILD_SHARED_LIBRARY)
    install(FILES shadowsocks.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()
