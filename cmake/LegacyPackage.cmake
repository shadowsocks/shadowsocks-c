# Preserve installed library filenames for existing build scripts and binaries.
# Unix aliases are relative symlinks so the installation remains relocatable.
# Windows uses copies because creating symlinks may require elevated privileges.
function(ss_legacy_library target directory filename source)
    # filename is supplied with its canonical project name replaced below.
    string(REPLACE "shadowsocks-c" "shadowsocks-libev" legacy "${filename}")
    if(WIN32)
        install(FILES "${source}" DESTINATION "${directory}" RENAME "${legacy}")
    else()
        install(CODE "file(MAKE_DIRECTORY \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${directory}\")
            file(CREATE_LINK \"$<TARGET_FILE_NAME:${target}>\"
                \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${directory}/${legacy}\" SYMBOLIC)")
    endif()
endfunction()

foreach(kind STATIC SHARED)
    if(SS_BUILD_${kind}_LIBRARY)
        string(TOLOWER "${kind}" suffix)
        set(target shadowsocks-c-${suffix})
        if(WIN32 AND kind STREQUAL "SHARED")
            ss_legacy_library(${target} "${CMAKE_INSTALL_BINDIR}"
                "${CMAKE_SHARED_LIBRARY_PREFIX}shadowsocks-c${CMAKE_SHARED_LIBRARY_SUFFIX}" "$<TARGET_FILE:${target}>")
            ss_legacy_library(${target} "${CMAKE_INSTALL_LIBDIR}"
                "${CMAKE_IMPORT_LIBRARY_PREFIX}shadowsocks-c${CMAKE_IMPORT_LIBRARY_SUFFIX}" "$<TARGET_LINKER_FILE:${target}>")
        elseif(kind STREQUAL "STATIC")
            ss_legacy_library(${target} "${CMAKE_INSTALL_LIBDIR}"
                "${CMAKE_STATIC_LIBRARY_PREFIX}shadowsocks-c${CMAKE_STATIC_LIBRARY_SUFFIX}" "$<TARGET_FILE:${target}>")
        else()
            ss_legacy_library(${target} "${CMAKE_INSTALL_LIBDIR}"
                "${CMAKE_SHARED_LIBRARY_PREFIX}shadowsocks-c${CMAKE_SHARED_LIBRARY_SUFFIX}" "$<TARGET_FILE:${target}>")
            if(APPLE)
                set(legacy_soname "${CMAKE_SHARED_LIBRARY_PREFIX}shadowsocks-c.2${CMAKE_SHARED_LIBRARY_SUFFIX}")
            else()
                set(legacy_soname "${CMAKE_SHARED_LIBRARY_PREFIX}shadowsocks-c${CMAKE_SHARED_LIBRARY_SUFFIX}.2")
            endif()
            ss_legacy_library(${target} "${CMAKE_INSTALL_LIBDIR}" "${legacy_soname}" "$<TARGET_FILE:${target}>")
        endif()
    endif()
endforeach()

if(SS_BUILD_STATIC_LIBRARY OR SS_BUILD_SHARED_LIBRARY)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-libev-config.cmake"
        "include(CMakeFindDependencyMacro)\nfind_dependency(shadowsocks-c \${shadowsocks-libev_FIND_VERSION} CONFIG PATHS \"\${CMAKE_CURRENT_LIST_DIR}/../shadowsocks-c\" NO_DEFAULT_PATH)\n")
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-libev-config.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/shadowsocks-libev)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/package/shadowsocks-c-config-version.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/shadowsocks-libev RENAME shadowsocks-libev-config-version.cmake)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/shadowsocks-c.pc"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig RENAME shadowsocks-libev.pc)
endif()
