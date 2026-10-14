# The event loop is libuv, used through the C++ layer in src/event.
add_library(ss_ev INTERFACE)
target_include_directories(ss_ev INTERFACE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ss_ev INTERFACE ss_uv Threads::Threads ${SS_MATH_LIBRARY} ${CMAKE_DL_LIBS})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(ss_ev INTERFACE rt)
endif()
