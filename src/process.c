/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ss_process.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;
#endif

struct ss_process {
    char *program;
    char **argv, **env;
    size_t argc, envc;
#ifdef _WIN32
    HANDLE child, job, monitor;
    uint16_t control_port;
#else
    pid_t pid;
#endif
};

static char *
copy_string(const char *text)
{
    size_t size = strlen(text) + 1;
    char *copy = ss_malloc(size);
    memcpy(copy, text, size);
    return copy;
}

struct ss_process *
ss_process_new(const char *program)
{
    struct ss_process *process = ss_malloc(sizeof(*process));
    memset(process, 0, sizeof(*process));
    process->program = copy_string(program);
    return process;
}

void
ss_process_arg(struct ss_process *process, const char *argument)
{
    process->argv = ss_realloc(process->argv, (process->argc + 2) * sizeof(char *));
    process->argv[process->argc++] = copy_string(argument);
    process->argv[process->argc] = NULL;
}

void
ss_process_env(struct ss_process *process, const char *name, const char *value)
{
    size_t size = strlen(name) + strlen(value) + 2;
    char *entry = ss_malloc(size);
    snprintf(entry, size, "%s=%s", name, value);
    process->env = ss_realloc(process->env, (process->envc + 2) * sizeof(char *));
    process->env[process->envc++] = entry;
    process->env[process->envc] = NULL;
}

#ifndef _WIN32
static bool
overridden(const struct ss_process *process, const char *entry)
{
    const char *equals = strchr(entry, '=');
    if (equals == NULL) {
        return false;
    }
    size_t length = (size_t)(equals - entry) + 1;
    for (size_t i = 0; i < process->envc; i++) {
        if (strncmp(entry, process->env[i], length) == 0) {
            return true;
        }
    }
    return false;
}

int
ss_process_start(struct ss_process *process, uint16_t control_port)
{
    (void)control_port;
    size_t count = 0, used = 0;
    while (environ[count] != NULL) {
        count++;
    }
    char **env = ss_malloc((count + process->envc + 1) * sizeof(char *));
    for (size_t i = 0; i < count; i++) {
        if (!overridden(process, environ[i])) {
            env[used++] = environ[i];
        }
    }
    for (size_t i = 0; i < process->envc; i++) {
        env[used++] = process->env[i];
    }
    env[used] = NULL;
    posix_spawnattr_t attr;
    int error = posix_spawnattr_init(&attr);
    if (error == 0) {
        sigset_t empty, defaults;
        sigemptyset(&empty);
        sigemptyset(&defaults);
        sigaddset(&defaults, SIGPIPE);
        sigaddset(&defaults, SIGTERM);
        sigaddset(&defaults, SIGINT);
        error = posix_spawnattr_setpgroup(&attr, 0);
        if (error == 0) error = posix_spawnattr_setsigmask(&attr, &empty);
        if (error == 0) error = posix_spawnattr_setsigdefault(&attr, &defaults);
        if (error == 0) error = posix_spawnattr_setflags(&attr,
            POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
        if (error == 0) error = posix_spawnp(&process->pid, process->program, NULL,
                                            &attr, process->argv, env);
        posix_spawnattr_destroy(&attr);
    }
    free(env);
    if (error != 0) {
        process->pid = 0;
        errno = error;
        return -1;
    }
    return 0;
}

bool
ss_process_running(struct ss_process *process)
{
    if (process == NULL || process->pid == 0) return false;
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    int result;
    do {
        result = waitid(P_PID, (id_t)process->pid, &info, WEXITED | WNOHANG | WNOWAIT);
    } while (result < 0 && errno == EINTR);
    /* Preserve the zombie until cleanup so its process-group ID cannot be
     * reused before all descendants have been signaled. */
    if (result < 0 && errno == ECHILD) process->pid = 0;
    return result == 0 && info.si_pid == 0;
}

static void
stop_process(struct ss_process *process)
{
    if (process->pid == 0) return;
    kill(-process->pid, SIGTERM);
    for (unsigned i = 0; i < 50 && ss_process_running(process); i++) {
        struct timespec delay = {0, 10000000};
        nanosleep(&delay, NULL);
    }
    if (process->pid != 0) {
        kill(-process->pid, SIGKILL);
        while (waitpid(process->pid, NULL, 0) < 0 && errno == EINTR) {}
        process->pid = 0;
    }
}
#else
static wchar_t *
wide_string(const char *text)
{
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (count == 0) return NULL;
    wchar_t *wide = ss_malloc((size_t)count * sizeof(wchar_t));
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, wide, count)) {
        free(wide);
        return NULL;
    }
    return wide;
}

static DWORD WINAPI
monitor_process(void *argument)
{
    struct ss_process *process = argument;
    WaitForSingleObject(process->child, INFINITE);
    if (process->control_port != 0) {
        SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd != INVALID_SOCKET) {
            struct sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(process->control_port);
            if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
                send(fd, "\0", 1, 0);
            }
            closesocket(fd);
        }
    }
    return 0;
}

static int
compare_environment(const void *left, const void *right)
{
    return _wcsicmp(*(const wchar_t *const *)left, *(const wchar_t *const *)right);
}

static wchar_t *
sort_environment(wchar_t *env)
{
    size_t count = 0, length = 1;
    for (wchar_t *entry = env; *entry; entry += wcslen(entry) + 1) {
        count++;
        length += wcslen(entry) + 1;
    }
    wchar_t **entries = ss_malloc((count + 1) * sizeof(*entries));
    size_t index = 0;
    for (wchar_t *entry = env; *entry; entry += wcslen(entry) + 1) entries[index++] = entry;
    qsort(entries, count, sizeof(*entries), compare_environment);
    wchar_t *sorted = ss_malloc((length + 1) * sizeof(*sorted)), *out = sorted;
    for (size_t i = 0; i < count; i++) {
        size_t size = wcslen(entries[i]) + 1;
        memcpy(out, entries[i], size * sizeof(*out));
        out += size;
    }
    *out++ = L'\0';
    *out = L'\0';
    free(entries);
    free(env);
    return sorted;
}

int
ss_process_start(struct ss_process *process, uint16_t control_port)
{
    /* Quote each argv element according to the Windows C runtime rules.
     * Double backslashes before a quote or the closing quote. */
    size_t capacity = 1;
    for (size_t i = 0; i < process->argc; i++) capacity += 2 * strlen(process->argv[i]) + 4;
    char *command = ss_malloc(capacity), *out = command;
    for (size_t i = 0; i < process->argc; i++) {
        if (i != 0) *out++ = ' ';
        *out++ = '"';
        const char *arg = process->argv[i];
        while (*arg != '\0') {
            size_t slashes = 0;
            while (*arg == '\\') { slashes++; arg++; }
            size_t copies = (*arg == '"' || *arg == '\0') ? slashes * 2 : slashes;
            while (copies-- != 0) *out++ = '\\';
            if (*arg == '\0') break;
            if (*arg == '"') *out++ = '\\';
            *out++ = *arg++;
        }
        *out++ = '"';
    }
    *out = '\0';
    wchar_t *wide_command = wide_string(command);
    free(command);
    if (wide_command == NULL) return -1;

    wchar_t *inherited = GetEnvironmentStringsW();
    if (inherited == NULL) { free(wide_command); return -1; }
    wchar_t **overrides = ss_malloc((process->envc + 1) * sizeof(wchar_t *));
    size_t total = 2;
    for (const wchar_t *entry = inherited; *entry; entry += wcslen(entry) + 1) total += wcslen(entry) + 1;
    for (size_t i = 0; i < process->envc; i++) {
        overrides[i] = wide_string(process->env[i]);
        if (overrides[i] == NULL) {
            for (size_t j = 0; j < i; j++) free(overrides[j]);
            free(overrides); FreeEnvironmentStringsW(inherited); free(wide_command);
            return -1;
        }
        total += wcslen(overrides[i]) + 1;
    }
    wchar_t *env = ss_malloc(total * sizeof(wchar_t)), *dest = env;
    for (const wchar_t *entry = inherited; *entry; entry += wcslen(entry) + 1) {
        const wchar_t *equals = wcschr(entry, L'=');
        bool replace = false;
        if (equals != NULL && equals != entry) {
            for (size_t i = 0; i < process->envc; i++) {
                if (_wcsnicmp(entry, overrides[i], (size_t)(equals - entry) + 1) == 0) replace = true;
            }
        }
        if (!replace) {
            size_t length = wcslen(entry) + 1;
            memcpy(dest, entry, length * sizeof(wchar_t)); dest += length;
        }
    }
    for (size_t i = 0; i < process->envc; i++) {
        size_t length = wcslen(overrides[i]) + 1;
        memcpy(dest, overrides[i], length * sizeof(wchar_t)); dest += length;
        free(overrides[i]);
    }
    *dest++ = L'\0'; *dest = L'\0';
    free(overrides); FreeEnvironmentStringsW(inherited);
    env = sort_environment(env);
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION child = {0};
    startup.cb = sizeof(startup);
    process->job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    BOOL ok = process->job != NULL && SetInformationJobObject(process->job,
        JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    if (ok) ok = CreateProcessW(NULL, wide_command, NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, env, NULL, &startup, &child);
    free(env); free(wide_command);
    if (ok) {
        process->child = child.hProcess;
        ok = AssignProcessToJobObject(process->job, child.hProcess);
        if (ok) ok = ResumeThread(child.hThread) != (DWORD)-1;
        CloseHandle(child.hThread);
    }
    if (!ok) {
        if (process->child) TerminateProcess(process->child, 1);
        return -1;
    }
    process->control_port = control_port;
    process->monitor = CreateThread(NULL, 0, monitor_process, process, 0, NULL);
    return process->monitor == NULL ? -1 : 0;
}

bool
ss_process_running(struct ss_process *process)
{
    return process != NULL && process->child != NULL &&
        WaitForSingleObject(process->child, 0) == WAIT_TIMEOUT;
}

static void
stop_process(struct ss_process *process)
{
    if (process->job) { CloseHandle(process->job); process->job = NULL; }
    if (process->monitor) {
        WaitForSingleObject(process->monitor, INFINITE);
        CloseHandle(process->monitor);
    }
    if (process->child) { WaitForSingleObject(process->child, INFINITE); CloseHandle(process->child); }
}
#endif

void
ss_process_free(struct ss_process *process)
{
    if (process == NULL) return;
    stop_process(process);
    for (size_t i = 0; i < process->argc; i++) free(process->argv[i]);
    for (size_t i = 0; i < process->envc; i++) free(process->env[i]);
    free(process->argv); free(process->env); free(process->program); free(process);
}
