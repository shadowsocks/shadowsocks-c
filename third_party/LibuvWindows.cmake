# libuv 1.52.1 passes const char ** to a converter that writes char **.
# GCC 14+ rejects this. Keep the archive untouched and use a mutable temporary
# in the extracted source, assigning it to the const public field afterwards.
if(WIN32)
    set(uv_util "${uv_SOURCE}/src/win/util.c")
    file(READ "${uv_util}" uv_util_content)
    set(uv_old [=[    uv__convert_utf16_to_utf8(cpu_brand,
                              cpu_brand_size / sizeof(WCHAR),
                              &(cpu_info->model));]=])
    set(uv_new [=[    char* model = NULL;
    uv__convert_utf16_to_utf8(cpu_brand,
                              cpu_brand_size / sizeof(WCHAR),
                              &model);
    cpu_info->model = model;]=])
    string(FIND "${uv_util_content}" "${uv_old}" uv_old_offset)
    string(FIND "${uv_util_content}" "${uv_new}" uv_new_offset)
    if(NOT uv_old_offset EQUAL -1)
        string(REPLACE "${uv_old}" "${uv_new}" uv_util_content "${uv_util_content}")
        file(WRITE "${uv_util}" "${uv_util_content}")
    elseif(uv_new_offset EQUAL -1)
        message(FATAL_ERROR "Bundled libuv changed; review the Windows CPU-info compatibility fix")
    endif()
endif()
