/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ss_process.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include <algorithm>
#include <array>
#include <string_view>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif
extern char **environ;
#endif

#ifndef _WIN32
#ifdef __APPLE__
typedef int ss_group_t; /* getgrouplist() takes int on macOS */
#else
typedef gid_t ss_group_t;
#endif
enum { SS_MAX_GROUPS = 64 };
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
    bool drop; /* switch to uid/gid/groups in the child */
    uid_t uid;
    gid_t gid;
    ss_group_t groups[SS_MAX_GROUPS];
    int ngroups;
#endif
};

static char *
copy_string(const char *text)
{
    size_t size = strlen(text) + 1;
    char *copy = (char *)ss_malloc(size);
    memcpy(copy, text, size);
    return copy;
}

struct ss_process *
ss_process_new(const char *program)
{
    struct ss_process *process = (struct ss_process *)ss_malloc(sizeof(*process));
    memset(process, 0, sizeof(*process));
    process->program = copy_string(program);
    return process;
}

void
ss_process_arg(struct ss_process *process, const char *argument)
{
    process->argv = (char **)ss_realloc(process->argv, (process->argc + 2) * sizeof(char *));
    process->argv[process->argc++] = copy_string(argument);
    process->argv[process->argc] = NULL;
}

void
ss_process_env(struct ss_process *process, const char *name, const char *value)
{
    size_t size = strlen(name) + strlen(value) + 2;
    char *entry = (char *)ss_malloc(size);
    snprintf(entry, size, "%s=%s", name, value);
    process->env = (char **)ss_realloc(process->env, (process->envc + 2) * sizeof(char *));
    process->env[process->envc++] = entry;
    process->env[process->envc] = NULL;
}

#ifndef _WIN32
int
ss_process_user(struct ss_process *process, const char *user)
{
    if (user == NULL || geteuid() != 0) {
        return 0; /* nothing to drop */
    }
    char buf[16 * 1024];
    struct passwd pwdbuf, *pwd = NULL;
    char *end = NULL;
    long uid  = strtol(user, &end, 10);
    int err   = (*user != '\0' && *end == '\0' && uid >= 0)
                ? getpwuid_r((uid_t)uid, &pwdbuf, buf, sizeof(buf), &pwd)
                : getpwnam_r(user, &pwdbuf, buf, sizeof(buf), &pwd);
    if (err != 0 || pwd == NULL) {
        LOGE("plugin: unknown user %s", user);
        return -1;
    }
    process->ngroups = SS_MAX_GROUPS;
    if (getgrouplist(pwd->pw_name, (ss_group_t)pwd->pw_gid, process->groups, &process->ngroups) == -1) {
        process->groups[0] = (ss_group_t)pwd->pw_gid; /* more than SS_MAX_GROUPS: keep the primary one */
        process->ngroups   = 1;
    }
    process->uid  = pwd->pw_uid;
    process->gid  = pwd->pw_gid;
    process->drop = true;
    return 0;
}

/* The executable execve() runs: `program` itself if it names a path, or the
 * first match on PATH, as posix_spawnp() would find it. */
using ProgramPath = std::array<char, PATH_MAX>;

static bool
set_path(ProgramPath &out, std::string_view dir, std::string_view program)
{
    std::string_view slash = dir.empty() ? "" : "/";
    if (dir.size() + slash.size() + program.size() >= out.size()) {
        return false;
    }
    auto end = std::copy(dir.begin(), dir.end(), out.begin());
    end      = std::copy(slash.begin(), slash.end(), end);
    end      = std::copy(program.begin(), program.end(), end);
    *end     = '\0';
    return true;
}

static std::string_view
env_value(const char *name)
{
    const char *value = getenv(name);
    return value != NULL ? std::string_view(value) : std::string_view();
}

static bool
find_program(std::string_view program, ProgramPath &out)
{
    if (program.find('/') != std::string_view::npos) {
        return set_path(out, {}, program);
    }
    std::string_view path = env_value("PATH");
    if (path.empty()) {
        path = "/usr/local/bin:/usr/bin:/bin";
    }
    for (;;) {
        // Not substr(): it can throw, which would pull in the C++ runtime.
        std::string_view::size_type colon = path.find(':');
        std::string_view dir(path.data(), colon != std::string_view::npos ? colon : path.size());
        if (set_path(out, dir, program) && access(out.data(), X_OK) == 0) {
            return true;
        }
        if (colon == std::string_view::npos) {
            return false;
        }
        path.remove_prefix(colon + 1);
    }
}

/* In the forked child: lose root, but keep the right to bind ports below
 * 1024 (on Linux), which a server-side plugin listening on 443 needs. Only
 * system calls from here on. */
static int
drop_in_child(const struct ss_process *process)
{
#ifdef __linux__
    (void)prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
#endif
    if (setgroups((size_t)process->ngroups, (const gid_t *)process->groups) != 0
        || setgid(process->gid) != 0 || setuid(process->uid) != 0) {
        return -1;
    }
    if (setuid(0) == 0) {
        return -1; /* root must be gone for good */
    }
#ifdef __linux__
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));
    data[0].effective = data[0].permitted = data[0].inheritable = 1U << CAP_NET_BIND_SERVICE;
    if (syscall(SYS_capset, &header, data) == 0) {
#ifdef PR_CAP_AMBIENT
        /* Ambient, so it survives execve() of a non-setcap binary. */
        (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0);
#endif
    }
#endif
    return 0;
}

static int
fork_as_user(struct ss_process *process, char **env)
{
    ProgramPath path;
    if (!find_program(process->program, path)) {
        return ENOENT;
    }
    /* The child reports a failed switch or exec through this pipe. */
    int report[2];
    if (pipe(report) != 0) {
        return errno;
    }
    (void)fcntl(report[1], F_SETFD, FD_CLOEXEC);
    pid_t pid = fork();
    if (pid == 0) {
        close(report[0]);
        (void)setpgid(0, 0);
        sigset_t empty;
        sigemptyset(&empty);
        (void)sigprocmask(SIG_SETMASK, &empty, NULL);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        int error = EPERM;
        if (drop_in_child(process) == 0) {
            execve(path.data(), process->argv, env); // NOLINT(clang-analyzer-optin.taint.GenericTaint): the PATH lookup posix_spawnp() would do
            error = errno;
        }
        ssize_t ignored = write(report[1], &error, sizeof(error));
        (void)ignored;
        _exit(127);
    }
    int error = pid < 0 ? errno : 0;
    close(report[1]);
    if (pid > 0) {
        int child_error = 0;
        ssize_t n;
        do {
            n = read(report[0], &child_error, sizeof(child_error));
        } while (n < 0 && errno == EINTR);
        if (n == (ssize_t)sizeof(child_error)) {
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
            error = child_error;
        } else {
            process->pid = pid;
        }
    }
    close(report[0]);
    return error;
}

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
    char **env = (char **)ss_malloc((count + process->envc + 1) * sizeof(char *));
    for (size_t i = 0; i < count; i++) {
        if (!overridden(process, environ[i])) {
            env[used++] = environ[i];
        }
    }
    for (size_t i = 0; i < process->envc; i++) {
        env[used++] = process->env[i];
    }
    env[used] = NULL;
    if (process->drop) {
        int error = fork_as_user(process, env);
        free(env); // heap-ok: plugin start, startup
        if (error != 0) {
            process->pid = 0;
            errno = error;
            return -1;
        }
        return 0;
    }
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
int
ss_process_user(struct ss_process *process, const char *user)
{
    (void)process;
    (void)user;
    return 0;
}

static wchar_t *
wide_string(const char *text)
{
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (count == 0) return NULL;
    wchar_t *wide = (wchar_t *)ss_malloc((size_t)count * sizeof(wchar_t));
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, wide, count)) {
        free(wide);
        return NULL;
    }
    return wide;
}

static DWORD WINAPI
monitor_process(void *argument)
{
    struct ss_process *process = (struct ss_process *)argument;
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
    wchar_t **entries = (wchar_t **)ss_malloc((count + 1) * sizeof(*entries));
    size_t index = 0;
    for (wchar_t *entry = env; *entry; entry += wcslen(entry) + 1) entries[index++] = entry;
    qsort(entries, count, sizeof(*entries), compare_environment);
    wchar_t *sorted = (wchar_t *)ss_malloc((length + 1) * sizeof(*sorted)), *out = sorted;
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
    char *command = (char *)ss_malloc(capacity), *out = command;
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
    wchar_t **overrides = (wchar_t **)ss_malloc((process->envc + 1) * sizeof(wchar_t *));
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
    wchar_t *env = (wchar_t *)ss_malloc(total * sizeof(wchar_t)), *dest = env;
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
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
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
