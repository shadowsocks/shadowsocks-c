include(CheckCCompilerFlag)
option(DISABLE_SSP "Disable stack protector" OFF)
if(NOT DISABLE_SSP AND NOT MSVC)
    check_c_compiler_flag(-fstack-protector-strong HAS_STACK_PROTECTOR)
endif()

function(ss_project_options target)
    set_property(TARGET ${target} PROPERTY NO_SYSTEM_FROM_IMPORTED TRUE)
    target_include_directories(${target} BEFORE PRIVATE ${MBEDTLS_INCLUDE_DIRS})
    if(WIN32)
        target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN __USE_MINGW_ANSI_STDIO=1)
        # MinGW can otherwise pull in libwinpthread/libgcc from the toolchain,
        # even when all explicitly selected dependencies are static archives.
        get_target_property(ss_target_type ${target} TYPE)
        # Zig already supplies its own runtime for DLLs; its -static switch
        # changes the output kind instead of just selecting static libraries.
        if(NOT ss_target_type STREQUAL "SHARED_LIBRARY" OR CMAKE_C_COMPILER_ID STREQUAL "GNU")
            target_link_options(${target} PRIVATE -static)
        endif()
    endif()
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(SS_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wno-deprecated-declarations -fno-strict-aliasing)
        # C++ sources: no exceptions or RTTI, and no locks around function
        # statics (the event loop is single-threaded). New C++ code also opts
        # into -Wextra through ss_strict_warnings(); modules ported from C get
        # it when they are rewritten.
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions -fno-rtti -fno-threadsafe-statics>)
        # libstdc++ 15 enables its assertions at -O0, and they call
        # __glibcxx_assert_fail from the C++ runtime, which the programs and
        # libshadowsocks-c must not need (scripts/check_cxx_runtime.py).
        target_compile_definitions(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:_GLIBCXX_NO_ASSERTIONS>)
        # GCC's C++ -Wall adds -Wsign-compare and -Wclass-memaccess, which C's
        # -Wall does not have. Modules converted from C keep the warning set
        # they were written against; ss_strict_warnings() turns both back on.
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-Wno-sign-compare -Wno-class-memaccess>)
        if(SS_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
        if(HAS_STACK_PROTECTOR)
            target_compile_options(${target} PRIVATE -fstack-protector-strong)
        endif()
        if(MINGW OR CYGWIN)
            target_compile_options(${target} PRIVATE -mno-ms-bitfields)
        endif()
    endif()
    if(LINUX)
        target_compile_definitions(${target} PRIVATE _GNU_SOURCE)
    endif()
    if(ENABLE_SANITIZERS)
        if(MSVC)
            message(FATAL_ERROR "ASan + UBSan requires GCC or Clang")
        endif()
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
    if(ENABLE_COVERAGE)
        target_compile_options(${target} PRIVATE -O0 --coverage)
        target_link_options(${target} PRIVATE --coverage)
    endif()
endfunction()

# Extra warnings for source files written as C++ from the start (src/core,
# src/event, src/crypto and their tests). Per file, so targets that also
# compile converted C modules keep those at -Wall. Source properties are
# directory-scoped: call this from the directory that defines the targets.
function(ss_strict_warnings)
    if(NOT MSVC)
        set_source_files_properties(${ARGN} PROPERTIES COMPILE_OPTIONS
            "-Wextra;$<$<CXX_COMPILER_ID:GNU>:-Wsign-compare>;$<$<CXX_COMPILER_ID:GNU>:-Wclass-memaccess>")
    endif()
endfunction()
