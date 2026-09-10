/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_PLATFORM_H
#define SS_PLATFORM_H
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include "ss_windows.h"
typedef SOCKET ss_socket_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
typedef int ss_socket_t;
#endif

/* Socket errors are separate from CRT errno on Windows. Return normalized
 * errno constants for portable branching without redefining libc names. */
static inline int
ss_socket_error(void)
{
#ifdef _WIN32
    int error = WSAGetLastError();
    switch (error) {
    case WSAEWOULDBLOCK: return EWOULDBLOCK;
    case WSAEINPROGRESS: return EINPROGRESS;
    case WSAEINTR: return EINTR;
    case WSAEINVAL: return EINVAL;
    case WSAEOPNOTSUPP: return EOPNOTSUPP;
    case WSAEPROTONOSUPPORT: return EPROTONOSUPPORT;
    case WSAENOPROTOOPT: return ENOPROTOOPT;
    case WSAECONNRESET: return ECONNRESET;
    case WSAENOTCONN: return ENOTCONN;
    case WSAETIMEDOUT: return ETIMEDOUT;
    default: return error;
    }
#else
    return errno;
#endif
}

static inline int
ss_socket_close(ss_socket_t fd)
{
#ifdef _WIN32
    return closesocket(fd);
#else
    return close(fd);
#endif
}

static inline ss_socket_t
ss_socket_noinherit(ss_socket_t fd)
{
#ifdef _WIN32
    if (fd != INVALID_SOCKET && !SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, 0)) {
        closesocket(fd);
        WSASetLastError(WSAEINVAL);
        return INVALID_SOCKET;
    }
#else
    if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
#endif
    return fd;
}

static inline ss_socket_t
ss_socket(int family, int type, int protocol)
{
    return ss_socket_noinherit(socket(family, type, protocol));
}

static inline ss_socket_t
ss_accept(ss_socket_t fd, struct sockaddr *address, socklen_t *length)
{
    return ss_socket_noinherit(accept(fd, address, length));
}

static inline int
ss_setsockopt(ss_socket_t fd, int level, int option, const void *value, socklen_t length)
{
#ifdef _WIN32
    return setsockopt(fd, level, option, (const char *)value, length);
#else
    return setsockopt(fd, level, option, value, length);
#endif
}

static inline const char *
ss_inet_ntop(int family, const void *address, char *text, socklen_t length)
{
#ifdef _WIN32
    return inet_ntop(family, (void *)address, text, length);
#else
    return inet_ntop(family, address, text, length);
#endif
}

static inline double
ss_monotonic_time(void)
{
#ifdef _WIN32
    LARGE_INTEGER counter, frequency;
    if (!QueryPerformanceCounter(&counter) || !QueryPerformanceFrequency(&frequency)) abort();
    return (double)counter.QuadPart / (double)frequency.QuadPart;
#else
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) abort();
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
#endif
}
#endif
