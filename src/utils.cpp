/*
 * utils.cpp - Misc utilities
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#ifndef __MINGW32__
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#else
#include <malloc.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sodium.h>

#include "utils.h"

#ifdef HAVE_SETRLIMIT
#include <sys/time.h>
#include <sys/resource.h>
#endif

#define INT_DIGITS 19           /* enough for 64 bit integer */

#ifdef LIB_ONLY
FILE *logfile;
#endif

#ifdef HAS_SYSLOG
int use_syslog = 0;
#endif

#ifndef __MINGW32__
void
ERROR(const char *s)
{
    char *msg = strerror(errno);
    LOGE("%s: %s", s, msg);
}

#endif

int use_tty = 1;

char *
ss_itoa(int i)
{
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char *p = buf + INT_DIGITS + 1;     /* points to terminating '\0' */
    if (i >= 0) {
        do {
            *--p = '0' + (i % 10);
            i   /= 10;
        } while (i != 0);
        return p;
    } else {                     /* i < 0 */
        do {
            *--p = '0' - (i % 10);
            i   /= 10;
        } while (i != 0);
        *--p = '-';
    }
    return p;
}

int
ss_isnumeric(const char *s)
{
    if (!s || !*s)
        return 0;
    while (isdigit((unsigned char)*s))
        ++s;
    return *s == '\0';
}

int
ss_parse_int(const char *s, int min_value, int max_value, int *out)
{
    char *endptr;
    long value;

    if (s == NULL || *s == '\0' || out == NULL || min_value > max_value) {
        return -1;
    }

    errno = 0;
    value = strtol(s, &endptr, 10);
    if (errno == ERANGE || endptr == s || *endptr != '\0' ||
        value < min_value || value > max_value) {
        return -1;
    }

    *out = (int)value;
    return 0;
}

int
ss_parse_uint16_port(const char *s, uint16_t *out)
{
    int value;

    if (out == NULL || ss_parse_int(s, 1, UINT16_MAX, &value) == -1) {
        return -1;
    }

    *out = (uint16_t)value;
    return 0;
}

/*
 * setuid() and setgid() for a specified user.
 */
int
run_as(const char *user)
{
#ifndef __MINGW32__
    if (user[0]) {
        /* Convert user to a long integer if it is a non-negative number.
         * -1 means it is a user name. */
        long uid = -1;
        if (ss_isnumeric(user)) {
            errno = 0;
            char *endptr;
            uid = strtol(user, &endptr, 10);
            if (errno || endptr == user)
                uid = -1;
        }

#ifdef HAVE_GETPWNAM_R
        struct passwd pwdbuf, *pwd;
        memset(&pwdbuf, 0, sizeof(struct passwd));
        size_t buflen;
        int err;

        /* The loop below gives up beyond 16 KiB, so one fixed buffer covers
         * every attempt. */
        char buf[16 * 1024];
        for (buflen = 128;; buflen *= 2) {

            /* Note that we use getpwnam_r() instead of getpwnam(),
             * which returns its result in a statically allocated buffer and
             * cannot be considered thread safe. */
            err = uid >= 0 ? getpwuid_r((uid_t)uid, &pwdbuf, buf, buflen, &pwd)
                  : getpwnam_r(user, &pwdbuf, buf, buflen, &pwd);

            if (err == 0 && pwd) {
                /* setgid first, because we may not be allowed to do it anymore after setuid */
                if (setgid(pwd->pw_gid) != 0) {
                    LOGE(
                        "Could not change group id to that of run_as user '%s': %s",
                        pwd->pw_name, strerror(errno));
                    return 0;
                }

#ifndef __CYGWIN__
                if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) {
                    LOGE("Could not change supplementary groups for user '%s'.", pwd->pw_name);
                    return 0;
                }
#endif

                if (setuid(pwd->pw_uid) != 0) {
                    LOGE(
                        "Could not change user id to that of run_as user '%s': %s",
                        pwd->pw_name, strerror(errno));
                    return 0;
                }
                break;
            } else if (err != ERANGE) {
                if (err) {
                    LOGE("run_as user '%s' could not be found: %s", user,
                         strerror(err));
                } else {
                    LOGE("run_as user '%s' could not be found.", user);
                }
                return 0;
            } else if (buflen >= 16 * 1024) {
                /* If getpwnam_r() seems defective, call it quits rather than
                 * keep on allocating ever larger buffers until we crash. */
                LOGE(
                    "getpwnam_r() requires more than %u bytes of buffer space.",
                    (unsigned)buflen);
                return 0;
            }
            /* Else try again with larger buffer. */
        }
#else
        /* No getpwnam_r() :-(  We'll use getpwnam() and hope for the best. */
        struct passwd *pwd;

        if (!(pwd = uid >= 0 ? getpwuid((uid_t)uid) : getpwnam(user))) {
            LOGE("run_as user %s could not be found.", user);
            return 0;
        }
        /* setgid first, because we may not allowed to do it anymore after setuid */
        if (setgid(pwd->pw_gid) != 0) {
            LOGE("Could not change group id to that of run_as user '%s': %s",
                 pwd->pw_name, strerror(errno));
            return 0;
        }
        if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) {
            LOGE("Could not change supplementary groups for user '%s'.", pwd->pw_name);
            return 0;
        }
        if (setuid(pwd->pw_uid) != 0) {
            LOGE("Could not change user id to that of run_as user '%s': %s",
                 pwd->pw_name, strerror(errno));
            return 0;
        }
#endif
    }
#else
    LOGE("run_as(): not implemented in MinGW port");
#endif

    return 1;
}

char *
ss_strndup(const char *s, size_t n)
{
    char *ret;

    size_t len = 0;
    while (len < n && s[len] != '\0') {
        len++;
    }

    ret = (char *)ss_malloc(len + 1);
    memcpy(ret, s, len);
    ret[len] = '\0';
    return ret;
}

void
FATAL(const char *msg)
{
    LOGE("%s", msg);
    exit(-1);
}

/* Set once startup is over (see core/heap_guard.hpp); allocations through
 * these helpers are counted from then on. */
int ss_heap_sealed            = 0;
size_t ss_heap_late_allocations = 0;

#define NOTE_ALLOCATION()             \
    do {                              \
        if (ss_heap_sealed)           \
            ss_heap_late_allocations++; \
    } while (0)

void *
ss_malloc(size_t size)
{
    NOTE_ALLOCATION();
    void *tmp = malloc(size);
    if (tmp == NULL)
        exit(EXIT_FAILURE);
    return tmp;
}

void *
ss_aligned_malloc(size_t size)
{
    NOTE_ALLOCATION();
    int err;
    void *tmp = NULL;
#ifdef HAVE_POSIX_MEMALIGN
    /* ensure 16 byte alignment */
    err = posix_memalign(&tmp, 16, size);
#elif __MINGW32__
    tmp = _aligned_malloc(size, 16);
    err = tmp == NULL;
#else
    err = -1;
#endif
    if (err) {
        return ss_malloc(size);
    } else {
        return tmp;
    }
}

void *
ss_realloc(void *ptr, size_t new_size)
{
    NOTE_ALLOCATION();
    void *resized = realloc(ptr, new_size);
    if (resized == NULL) {
        free(ptr);
        ptr = NULL;
        exit(EXIT_FAILURE);
    }
    return resized;
}

int
ss_is_ipv6addr(const char *addr)
{
    return strcmp(addr, ":") > 0;
}

/* [cli_short_s]
\par `-s <server_host>`
For clients, set a server endpoint as `HOST:PORT` or `[IPv6]:PORT`; host-only values use the legacy `-p` or configured fallback. Bare IPv6 is never split at its last colon. For server and manager, set the listening address.
[cli_short_s] */

/* [cli_short_p]
\par `-p <server_port>`
For clients, set the legacy fallback port for server values without an embedded port. For ss-server, set the listening port.
[cli_short_p] */

/* [cli_short_l]
\par `-l <local_port>`
Set the local port number.
[cli_short_l] */

/* [cli_short_k]
\par `-k <password>`
Set the password. The server and the client should use the same password.
[cli_short_k] */

/* [cli_long_password]
\par `--password <password>`
Set the password. The server and the client should use the same password.
[cli_long_password] */

/* [cli_long_key]
\par `--key <key_in_base64>`
Set the key directly. The key should be encoded with URL-safe Base64.
[cli_long_key] */

/* [cli_long_server_url]
\par `--server-url <ss_url>`
Take the server address, port, cipher, password and any SIP003 plugin
from a single `ss://` URL, as produced by most clients and by
*shadowsocks-rust*'s `ssurl`. Both the SIP002 form
(`ss://base64(method:password)@host:port/?plugin=...#tag`) and the older
`ss://base64(method:password@host:port)` form are accepted. Options given
later on the command line override the values taken from the URL.
[cli_long_server_url] */

/* [cli_short_m]
\par `-m <encrypt_method>`
Set the cipher. The default is `chacha20-ietf-poly1305`.

AEAD cipher names from the source (availability depends on the build):
\snippet aead.cpp cli-aead-ciphers

The unauthenticated stream ciphers (`aes-256-cfb`, `chacha20-ietf`, `rc4-md5`
and the like) are no longer supported.

The `2022-blake3-*` ciphers implement Shadowsocks 2022 (SIP022). They require
a base64-encoded pre-shared key supplied with `--key` or `--password` (*-k*): 16 bytes for
2022-blake3-aes-128-gcm and 32 bytes for the other 2022 ciphers.
Generate a 32-byte key with `openssl rand -base64 32`.
Passwords are not stretched into keys for these ciphers.
[cli_short_m] */

/* [cli_short_a]
\par `-a <user_name>`
Run as a specific user.
[cli_short_a] */

/* [cli_short_f]
\par `-f <pid_file>`
Start shadowsocks as a daemon with specific pid file.
[cli_short_f] */

/* [cli_short_t]
\par `-t <timeout>`
Set the socket timeout in seconds. The default value is 60.
[cli_short_t] */

/* [cli_short_c]
\par `-c <config_file>`
Use a configuration file.

Refer to `shadowsocks-c`(8) `CONFIG FILE` section for more details.
[cli_short_c] */

/* [cli_short_n]
\par `-n <number>`
Specify the maximum number of open files. Requires a platform with setrlimit support.
[cli_short_n] */

/* [cli_short_i]
\par `-i <interface>`
Send outbound traffic through the specified network interface where supported by the platform.
[cli_short_i] */

/* [cli_short_b]
\par `-b <local_address>`
Set the local address to bind for the client listener.
[cli_short_b] */

/* [cli_short_u]
\par `-u`
Enable UDP relay.
[cli_short_u] */

/* [cli_short_U]
\par `-U`
Enable UDP relay and disable TCP relay.
[cli_short_U] */

/* [cli_short_6]
\par `-6`
Resolve hostname to IPv6 address first.
[cli_short_6] */

/* [cli_long_printable_salt]
\par `--printable-salt`
Experimental client TCP salt camouflage, disabled by default. Config key: `"printable_salt": true`
(ss-local only). Randomly choose 6-12 leading
salt bytes and sample each as printable ASCII (0x20-0x7e). Requires chacha20-ietf-poly1305 or
aes-256-gcm. Adds no framing bytes; leaves UDP and server responses unchanged.
The 32-byte salt retains at least 238 bits of entropy. Salt uniqueness
remains essential. This is not TLS impersonation or proven censorship resistance.
[cli_long_printable_salt] */

/* [cli_long_fast_open]
\par `--fast-open`
Enable TCP Fast Open where supported by the operating system.
[cli_long_fast_open] */

/* [cli_long_reuse_port]
\par `--reuse-port`
Enable port reuse where supported by the operating system.
[cli_long_reuse_port] */

/* [cli_long_acl]
\par `--acl <acl_config>`
Enable ACL (Access Control List) and specify config file.
[cli_long_acl] */

/* [cli_long_mtu]
\par `--mtu <MTU>`
Specify the MTU of your network interface.
[cli_long_mtu] */

/* [cli_long_mptcp]
\par `--mptcp`
Enable Multipath TCP.

Only available with MPTCP enabled Linux kernel.
[cli_long_mptcp] */

/* [cli_long_no_delay]
\par `--no-delay`
Enable TCP_NODELAY.
[cli_long_no_delay] */

/* [cli_long_max_connections]
\par `--max-connections <number>`
Serve at most this many TCP connections at once (default: 1024). Their
memory is reserved at startup; a connection beyond the limit is refused
until another one closes.
[cli_long_max_connections] */

/* [cli_long_max_udp_sessions]
\par `--max-udp-sessions <number>`
Keep at most this many UDP associations (default: 256 for clients, 512
for ss-server). When the table is full, the least recently used one is
dropped.
[cli_long_max_udp_sessions] */

/* [cli_long_max_dns_queries]
\par `--max-dns-queries <number>`
Run at most this many DNS lookups at once (default: the connection limit;
ss-server adds 64). Beyond the limit ss-server closes the connection that
needed the lookup, and ss-local applies its ACL without the address.
[cli_long_max_dns_queries] */

/* [cli_long_tcp_incoming_sndbuf]
\par `--tcp-incoming-sndbuf <size>`
Set TCP send buffer size for incoming connections.
[cli_long_tcp_incoming_sndbuf] */

/* [cli_long_tcp_incoming_rcvbuf]
\par `--tcp-incoming-rcvbuf <size>`
Set TCP receive buffer size for incoming connections.
[cli_long_tcp_incoming_rcvbuf] */

/* [cli_long_tcp_outgoing_sndbuf]
\par `--tcp-outgoing-sndbuf <size>`
Set TCP send buffer size for outgoing connections.
[cli_long_tcp_outgoing_sndbuf] */

/* [cli_long_tcp_outgoing_rcvbuf]
\par `--tcp-outgoing-rcvbuf <size>`
Set TCP receive buffer size for outgoing connections.
[cli_long_tcp_outgoing_rcvbuf] */

/* [cli_long_plugin]
\par `--plugin <plugin_name>`
Enable SIP003 plugin. (Experimental)
[cli_long_plugin] */

/* [cli_long_plugin_opts]
\par `--plugin-opts <plugin_options>`
Set SIP003 plugin options. (Experimental)
[cli_long_plugin_opts] */

/* [cli_short_v]
\par `-v`
Enable verbose mode.
[cli_short_v] */

/* [cli_short_h]
\par `-h`
Print help message.
[cli_short_h] */

/* [cli_long_help]
\par `--help`
Print help message.
[cli_long_help] */

/* [cli_short_A]
\par `-A`
Deprecated one-time authentication option. Exits with an error; use AEAD ciphers instead.
[cli_short_A] */

/* [cli_short_S]
\par `-S <path>`
Android only: UNIX socket path for traffic statistics.
[cli_short_S] */

/* [cli_short_V]
\par `-V`
Android only: enable VPN socket protection.
[cli_short_V] */

/* [cli_short_L]
\par `-L <addr:port>`
Destination server address and port for local port forwarding.
[cli_short_L] */

/* [cli_short_T]
\par `-T`
Use TPROXY instead of REDIRECT for TCP traffic. Requires Linux TPROXY support.
[cli_short_T] */

/* [cli_short_d]
\par `-d <addr>`
Configure name servers for the internal c-ares DNS resolver. By default it uses the system resolver configuration.
[cli_short_d] */

/* [cli_short_D]
\par `-D <path>`
Set the working directory of ss-manager.
[cli_short_D] */

/* [cli_long_workdir]
\par `--workdir <path>`
Set the working directory of ss-manager (alias for *-D*).
[cli_long_workdir] */

/* [cli_long_manager_address]
\par `--manager-address <address>`
Set the manager control address: a UNIX domain socket path or an IP address and port.
[cli_long_manager_address] */

/* [cli_long_executable]
\par `--executable <path>`
Set the executable path of ss-server used by ss-manager.
[cli_long_executable] */

/* [cli_long_nftables_sets]
\par `--nftables-sets <sets>`
Linux builds with USE_NFTABLES only: add malicious IP addresses to nftables sets. Format: `[<table1>:]<set1>[,[<table2>:]<set2>...]`.
[cli_long_nftables_sets] */

/* [cli_long_version]
\par `--version`
Print the program name and version to standard output and exit successfully.
[cli_long_version] */

/* [cli_long_tcp_only]
\par `--tcp-only`
Enable TCP relay only, overriding the configuration file's mode.
The last of `--tcp-only`, `--udp`, and `--udp-only` wins.
[cli_long_tcp_only] */

/* [cli_long_ipv4_first]
\par `--ipv4-first`
Prefer IPv4 DNS results, overriding `ipv6_first` in the configuration file.
This is an address preference, not a restriction to IPv4. The last of
`--ipv4-first` and `--ipv6-first` wins.
[cli_long_ipv4_first] */

static const char *
cli_program(void)
{
#ifdef MODULE_LOCAL
    return "ss-local";
#elif defined(MODULE_REMOTE)
    return "ss-server";
#elif defined(MODULE_TUNNEL)
    return "ss-tunnel";
#elif defined(MODULE_REDIR)
    return "ss-redir";
#elif defined(MODULE_MANAGER)
    return "ss-manager";
#else
    return "shadowsocks-c";
#endif
}

void
cli_version(void)
{
    printf("%s (shadowsocks-c) %s\n", cli_program(), VERSION);
}

void
cli_error(const char *message, int option, const char *token)
{
    fprintf(stderr, "%s: %s", cli_program(), message);
    /* Report option names, never attached passwords or positional values. */
    if (token != NULL && token[0] == '-' && token[1] == '-') {
        size_t length = 2;
        while (isalnum((unsigned char)token[length]) || token[length] == '-')
            length++;
        if (length > 2 && length < 80)
            fprintf(stderr, " '%.*s'", (int)length, token);
    } else if (option > 0 && option < 128 && isalnum((unsigned char)option)) {
        fprintf(stderr, " '-%c'", option);
    }
    fprintf(stderr, ". Try '%s --help'.\n", cli_program());
    exit(2);
}

static void
cli_help_option(const char *flags, const char *description)
{
    printf("  %-36s %s\n", flags, description);
}

void
usage(void)
{
    cli_version();
    printf("Usage: %s [options]\n\n", cli_program());
    puts("Connection:");
#if defined(MODULE_REMOTE) || defined(MODULE_MANAGER)
    cli_help_option("-s, --listen-address HOST", "Server listening address; may be repeated.");
#ifdef MODULE_REMOTE
    cli_help_option("-p, --listen-port PORT", "Server listening port.");
    cli_help_option("-b, --outbound-address ADDRESS", "Source address for outbound connections.");
#endif
#else
    cli_help_option("-s, --server HOST:PORT", "Remote endpoint; IPv6: [ADDRESS]:PORT. Repeatable.");
    cli_help_option("-p, --server-port PORT", "Legacy fallback for servers without a port.");
    cli_help_option("-b, --listen-address ADDRESS", "Local address to bind.");
    cli_help_option("-l, --listen-port PORT", "Local listening port.");
#endif
#ifdef MODULE_LOCAL
    cli_help_option("--server-url URL", "Import an ss:// URL; later options override it.");
#endif
#ifdef MODULE_TUNNEL
    cli_help_option("-L, --destination HOST:PORT", "Destination for local port forwarding.");
#endif
    puts("\nConfiguration and credentials:");
    cli_help_option("-c, --config FILE", "Read JSON configuration.");
    cli_help_option("-m, --cipher NAME", "Cipher (default: chacha20-ietf-poly1305).");
    cli_help_option("-k, --password SECRET", "Password, or a base64 pre-shared key for AEAD-2022.");
#ifndef MODULE_MANAGER
    cli_help_option("--key BASE64", "Use an explicit base64 key instead of a password.");
#endif
    puts("  AEAD-2022: 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm,");
    puts("             2022-blake3-chacha20-poly1305.");
    puts("\nTransport and networking:");
    cli_help_option("--tcp-only", "TCP only (default); overrides the configured mode.");
    cli_help_option("-u, --udp", "Enable both TCP and UDP relay.");
    cli_help_option("-U, --udp-only", "Enable UDP relay only.");
    cli_help_option("--ipv4-first", "Prefer IPv4 DNS results; overrides configuration.");
    cli_help_option("-6, --ipv6-first", "Prefer IPv6 DNS results.");
    cli_help_option("-t, --timeout SECONDS", "Socket timeout (default: 60).");
#ifndef MODULE_REDIR
    cli_help_option("-i, --interface NAME", "Outbound network interface, where supported.");
#endif
#if defined(MODULE_REMOTE) || defined(MODULE_MANAGER)
    cli_help_option("-d, --nameserver ADDRESS", "Name servers for the internal DNS resolver.");
#endif
#ifdef MODULE_REDIR
    cli_help_option("-T, --tproxy", "Use TPROXY for TCP; UDP always requires TPROXY.");
#endif
    cli_help_option("--mtu BYTES", "Network MTU (0 selects the default).");
    cli_help_option("--fast-open", "Enable TCP Fast Open where supported.");
    cli_help_option("--reuse-port", "Enable port reuse where supported.");
    cli_help_option("--no-delay", "Enable TCP_NODELAY.");
#ifndef MODULE_MANAGER
    cli_help_option("--max-connections NUMBER", "TCP connections served at once (default: 1024).");
    cli_help_option("--max-udp-sessions NUMBER", "UDP associations kept (default: 256; ss-server 512).");
#endif
#if defined(MODULE_REMOTE) || (defined(MODULE_LOCAL) && !defined(MODULE_TUNNEL) && !defined(MODULE_REDIR))
    cli_help_option("--max-dns-queries NUMBER", "DNS lookups in flight (default: the connection limit).");
#endif
#ifdef MODULE_LOCAL
    cli_help_option("--printable-salt", "Experimental printable TCP salt (chacha20-ietf-poly1305/aes-256-gcm only).");
#endif
#if !defined(MODULE_MANAGER) && (!defined(MODULE_REMOTE) || defined(__linux__))
    cli_help_option("--mptcp", "Enable Multipath TCP where supported.");
#endif
#ifndef MODULE_MANAGER
    cli_help_option("--tcp-incoming-sndbuf BYTES", "Incoming TCP send buffer (0: system default).");
    cli_help_option("--tcp-incoming-rcvbuf BYTES", "Incoming TCP receive buffer (0: system default).");
    cli_help_option("--tcp-outgoing-sndbuf BYTES", "Outgoing TCP send buffer (0: system default).");
    cli_help_option("--tcp-outgoing-rcvbuf BYTES", "Outgoing TCP receive buffer (0: system default).");
#endif
    puts("\nAccess control and plugins:");
#if defined(MODULE_LOCAL) || defined(MODULE_REMOTE) || defined(MODULE_MANAGER)
    cli_help_option("--acl FILE", "Access control list.");
#endif
#if defined(MODULE_REMOTE) && defined(__linux__) && defined(USE_NFTABLES)
    cli_help_option("--nftables-sets SETS", "Record malicious IPs in [table:]set[,set...] entries.");
#endif
    cli_help_option("--plugin NAME", "SIP003 plugin (requires plugin support in this build).");
    cli_help_option("--plugin-opts OPTIONS", "Options passed to the SIP003 plugin.");
    puts("\nProcess and diagnostics:");
    cli_help_option("-a, --user USER", "Run as the specified user.");
    cli_help_option("-f, --pid-file FILE", "Daemonize and write the process ID to FILE.");
#ifdef HAVE_SETRLIMIT
    cli_help_option("-n, --nofile COUNT", "Maximum number of open files.");
#endif
#if defined(MODULE_REMOTE) || defined(MODULE_MANAGER)
    cli_help_option("--manager-address ADDRESS", "Manager UNIX socket path or IP address and port.");
#endif
#ifdef MODULE_MANAGER
    cli_help_option("--executable PATH", "ss-server executable used for managed servers.");
    cli_help_option("-D, --workdir DIRECTORY", "Working directory for managed servers.");
#endif
#if defined(__ANDROID__) && (defined(MODULE_LOCAL) || defined(MODULE_TUNNEL))
    cli_help_option("-V, --vpn", "Enable Android VPN socket protection.");
#ifdef MODULE_LOCAL
    cli_help_option("-S, --stat-path PATH", "Android traffic-statistics socket.");
#endif
#endif
    cli_help_option("-v, --verbose", "Enable verbose logging.");
    cli_help_option("-h, --help", "Show this help and exit.");
    cli_help_option("--version", "Show the version and exit.");
    puts("\nOptions apply in command-line order; later mode and address-family flags win.");
    puts("No positional arguments are accepted. Use --option=value for values starting with '-'.");
    puts("The obsolete -A option is rejected; use an AEAD cipher instead.");
    puts("Manual: https://shadowsocks.github.io/shadowsocks-c/");
}

void
daemonize(const char *path)
{
#ifndef __MINGW32__
    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
     * we can exit the parent process. */
    if (pid > 0) {
        FILE *file = fopen(path, "w");
        if (file == NULL) {
            FATAL("Invalid pid file\n");
        }

        fprintf(file, "%d", (int)pid);
        fclose(file);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null > 0) {
        /* Redirect to null device  */
        dup2(dev_null, STDOUT_FILENO);
        dup2(dev_null, STDERR_FILENO);
    } else {
        /* Close the standard file descriptors */
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    /* Close the standard file descriptors */
    close(STDIN_FILENO);
#else
    LOGE("daemonize(): not implemented in MinGW port");
#endif
}

#ifdef HAVE_SETRLIMIT
int
set_nofile(int nofile)
{
    struct rlimit limit = { (rlim_t)nofile, (rlim_t)nofile }; /* set both soft and hard limit */

    if (nofile <= 0) {
        FATAL("nofile must be greater than 0\n");
    }

    if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
        if (errno == EPERM) {
            LOGE(
                "insufficient permission to change NOFILE, not starting as root?");
            return -1;
        } else if (errno == EINVAL) {
            LOGE("invalid nofile, decrease nofile and try again");
            return -1;
        } else {
            LOGE("setrlimit failed: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}

#endif

char *
get_default_conf(void)
{
#ifndef __MINGW32__
    static char sysconf[] = "/etc/shadowsocks-libev/config.json";
    static char userconf[PATH_MAX];
    char *conf_home;

    conf_home = getenv("XDG_CONFIG_HOME");

    if (!conf_home) {
        // HOME may be unset (e.g. when started by an init system)
        const char *home = getenv("HOME");
        if (home == NULL) {
            return sysconf;
        }
        snprintf(userconf, sizeof(userconf), "%s%s", home,
                 "/.config/shadowsocks-libev/config.json");
    } else {
        snprintf(userconf, sizeof(userconf), "%s%s", conf_home,
                 "/shadowsocks-libev/config.json");
    }

    // Check if the user-specific config exists.
    if (access(userconf, F_OK) != -1)
        return userconf;

    // If not, fall back to the system-wide config.
    return sysconf;
#else
    return (char *)"config.json";
#endif
}

uint16_t
load16_be(const void *s)
{
    const uint8_t *in = (const uint8_t *)s;
    return ((uint16_t)in[0] << 8)
           | ((uint16_t)in[1]);
}

int
get_mptcp(int enable)
{
    const char oldpath[] = "/proc/sys/net/mptcp/mptcp_enabled";

    if (enable) {
        // Check if kernel has out-of-tree MPTCP support.
        if (access(oldpath, F_OK) != -1)
            return 1;

        // Otherwise, just use IPPROTO_MPTCP.
        return -1;
    }

    return 0;
}
