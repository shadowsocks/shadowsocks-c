include(CMakePackageConfigHelpers)
if(SS_BUILD_STATIC_LIBRARY OR SS_BUILD_SHARED_LIBRARY)
set(SS_SYSTEM_DEPENDENCIES "")
set(SS_PC_PRIVATE "")
set(private_links)
set(private_content "# Generated private linkage for the installed static library.\n")
if(SS_BUILD_STATIC_LIBRARY)
    set(private_targets bloom blake3 ss_ev)
    if(SS_DEPENDENCY_MODE STREQUAL "bundled")
        list(APPEND private_targets ss_sodium ss_mbedcrypto ss_uv ss_cares)
        if(SS_ENABLE_REGEX)
            list(APPEND private_targets ss_pcre2)
        endif()
    else()
        set(SS_SYSTEM_DEPENDENCIES
            "list(APPEND CMAKE_MODULE_PATH \"\${CMAKE_CURRENT_LIST_DIR}/modules\")\n    find_dependency(MbedTLS ${MBEDTLS_VERSION} EXACT)\n    find_dependency(Sodium)\n    find_dependency(Cares)\n    find_library(SS_CONSUMER_UV NAMES uv REQUIRED)")
        if(SS_ENABLE_REGEX)
            string(APPEND SS_SYSTEM_DEPENDENCIES "\n    find_dependency(PCRE2)")
            list(APPEND private_links "\${PCRE2_LIBRARY}")
            string(APPEND SS_PC_PRIVATE " -lpcre2-8")
        endif()
        list(APPEND private_links "\${SODIUM_LIBRARY}" "\${MBEDTLS_CRYPTO_LIBRARY}"
            "\${CARES_LIBRARY}"  )
        string(APPEND SS_PC_PRIVATE " -lsodium -lmbedcrypto -lcares")
        install(FILES cmake/FindMbedTLS.cmake cmake/FindSodium.cmake
            cmake/FindCares.cmake cmake/FindPCRE2.cmake cmake/mbedtls_version_check.c
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/shadowsocks-c/modules)
    endif()
    foreach(target IN LISTS private_targets)
        install(FILES $<TARGET_FILE:${target}>
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/shadowsocks-c)
        list(APPEND private_links "\${_ss_libdir}/shadowsocks-c/$<TARGET_FILE_NAME:${target}>")
        string(APPEND SS_PC_PRIVATE " \${libdir}/shadowsocks-c/$<TARGET_FILE_NAME:${target}>")
    endforeach()
    if(SS_DEPENDENCY_MODE STREQUAL "system")
        list(APPEND private_links "\${SS_CONSUMER_UV}")
        string(APPEND SS_PC_PRIVATE " -luv")
    endif()
    list(APPEND private_links Threads::Threads ${SS_MATH_LIBRARY} ${CMAKE_DL_LIBS})
    if(WIN32)
        list(APPEND private_links ws2_32 iphlpapi bcrypt advapi32 user32 userenv psapi dbghelp ole32 shell32)
        string(APPEND SS_PC_PRIVATE " -lws2_32 -liphlpapi -lbcrypt -ladvapi32 -luser32 -luserenv -lpsapi -ldbghelp -lole32 -lshell32")
    else()
        string(APPEND SS_PC_PRIVATE " -lm -pthread")
        if(APPLE)
            list(APPEND private_links resolv)
            string(APPEND SS_PC_PRIVATE " -lresolv")
        endif()
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND private_links rt)
        string(APPEND SS_PC_PRIVATE " -lrt")
    endif()
    # Resolve libdir relative to this installed config, supporting --prefix relocation.
    file(RELATIVE_PATH libdir_from_config "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}/cmake/shadowsocks-c" "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
    string(APPEND private_content "get_filename_component(_ss_libdir \"\${CMAKE_CURRENT_LIST_DIR}/${libdir_from_config}\" ABSOLUTE)\n")
    string(APPEND private_content "set_property(TARGET shadowsocks::static PROPERTY INTERFACE_LINK_LIBRARIES \"${private_links}\")\n")
endif()
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-private.cmake" CONTENT "${private_content}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-private.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/shadowsocks-c)

set(SS_STATIC_FILENAME "${CMAKE_STATIC_LIBRARY_PREFIX}shadowsocks-c${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(SS_SHARED_FILENAME "${CMAKE_SHARED_LIBRARY_PREFIX}shadowsocks-c${CMAKE_SHARED_LIBRARY_SUFFIX}")
set(SS_SHARED_IMPLIB "${CMAKE_IMPORT_LIBRARY_PREFIX}shadowsocks-c${CMAKE_IMPORT_LIBRARY_SUFFIX}")
configure_package_config_file(cmake/shadowsocks-c-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-c-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/shadowsocks-c
    PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_BINDIR CMAKE_INSTALL_INCLUDEDIR)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-c-config-version.cmake"
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-c-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-c-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/shadowsocks-c)
file(RELATIVE_PATH SS_PC_PREFIX_RELATIVE "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}/pkgconfig" "${CMAKE_CURRENT_BINARY_DIR}")
configure_file(cmake/shadowsocks-c.pc.cmake "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-c.pc.in" @ONLY)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/shadowsocks-c.pc"
    INPUT "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-c.pc.in")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/shadowsocks-c.pc" DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()

install(FILES COPYING LICENSE third_party/README.md third_party/manifest.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/shadowsocks-c)
install(FILES third_party/bloom/LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/shadowsocks-c/bloom)
install(DIRECTORY src/blake3/ DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/shadowsocks-c/blake3
    FILES_MATCHING PATTERN "LICENSE*")

include(${PROJECT_SOURCE_DIR}/cmake/LegacyPackage.cmake)
