# Portable C backend: no assembler or platform build scripts needed. SIMD
# implementations compile to empty translation units unless enabled by probes.
file(READ "${sodium_SOURCE}/src/libsodium/Makefile.am" sodium_makefile)
string(REGEX MATCHALL "[a-zA-Z0-9_/-]+\\.c([ \n\r]|$)" sodium_relative_sources "${sodium_makefile}")
set(sodium_sources)
foreach(source IN LISTS sodium_relative_sources)
    string(STRIP "${source}" source)
    list(APPEND sodium_sources "${sodium_SOURCE}/src/libsodium/${source}")
endforeach()
list(REMOVE_DUPLICATES sodium_sources)
set(VERSION 1.0.22)
set(SODIUM_LIBRARY_VERSION_MAJOR 26)
set(SODIUM_LIBRARY_VERSION_MINOR 4)
set(SODIUM_LIBRARY_MINIMAL_DEF "")
configure_file("${sodium_SOURCE}/src/libsodium/include/sodium/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/sodium-include/sodium/version.h" @ONLY)
configure_file("${sodium_SOURCE}/src/libsodium/include/sodium/export.h"
    "${CMAKE_CURRENT_BINARY_DIR}/sodium-include/sodium/export.h" COPYONLY)
add_library(ss_sodium STATIC ${sodium_sources})
target_include_directories(ss_sodium PUBLIC
    "${CMAKE_CURRENT_BINARY_DIR}/sodium-include"
    "${sodium_SOURCE}/src/libsodium/include"
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/sodium-include/sodium" "${sodium_SOURCE}/src/libsodium/include/sodium")
target_compile_definitions(ss_sodium PUBLIC SODIUM_STATIC PRIVATE DEV_MODE=1)
if(NOT MSVC)
    target_compile_options(ss_sodium PRIVATE -fno-strict-aliasing -fwrapv)
endif()
if(WIN32)
    target_link_libraries(ss_sodium PUBLIC bcrypt)
endif()
set(SODIUM_INCLUDE_DIRS "${CMAKE_CURRENT_BINARY_DIR}/sodium-include;${sodium_SOURCE}/src/libsodium/include" PARENT_SCOPE)

if(CMAKE_USE_PTHREADS_INIT)
    target_compile_definitions(ss_sodium PRIVATE HAVE_PTHREAD=1)
    target_link_libraries(ss_sodium PUBLIC Threads::Threads)
endif()

# Upstream known-answer tests validate this project's portable CMake adapter.
if(BUILD_TESTING)
    foreach(name aead_chacha20poly1305 aead_xchacha20poly1305 auth auth2
                 chacha20 stream stream2 stream3 stream4 randombytes
                 sodium_core sodium_utils sodium_utils2 sodium_utils3)
        if(EXISTS "${sodium_SOURCE}/test/default/${name}.c")
            add_executable(sodium_test_${name} "${sodium_SOURCE}/test/default/${name}.c")
            target_link_libraries(sodium_test_${name} PRIVATE ss_sodium)
            target_include_directories(sodium_test_${name} PRIVATE "${sodium_SOURCE}/test/quirks")
            target_compile_definitions(sodium_test_${name} PRIVATE
                TEST_SRCDIR="${sodium_SOURCE}/test/default")
            add_test(NAME sodium_${name} COMMAND sodium_test_${name})
            set_tests_properties(sodium_${name} PROPERTIES LABELS "vendor" TIMEOUT 120)
        endif()
    endforeach()
endif()
