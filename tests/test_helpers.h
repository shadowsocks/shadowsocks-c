#ifndef SS_TEST_HELPERS_H
#define SS_TEST_HELPERS_H
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "platform.h"

static inline void test_network_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}
static inline void test_network_init(void)
{
#ifdef _WIN32
    WSADATA data;
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    assert(atexit(test_network_cleanup) == 0);
#endif
}
static inline FILE *test_tempfile(char *path, size_t size)
{
#ifdef _WIN32
    char directory[MAX_PATH];
    DWORD length = GetTempPathA(sizeof(directory), directory);
    assert(length != 0 && length < sizeof(directory));
    assert(size >= MAX_PATH);
    assert(GetTempFileNameA(directory, "ssc", 0, path) != 0);
    return fopen(path, "w");
#else
    assert(snprintf(path, size, "/tmp/ss-test.XXXXXX") < (int)size);
    int fd = mkstemp(path);
    assert(fd >= 0);
    return fdopen(fd, "w");
#endif
}
#endif
