// SPDX-License-Identifier: GPL-3.0-or-later
// Child process management (src/process.cpp): spawn failure, argument and
// environment passing, and exit detection. The test binary re-executes itself
// as the child via --child / --exit.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "ss_process.h"
#include "test_helpers.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

extern "C" {
int verbose = 0;
}

namespace {

void pause_tick()
{
#ifdef _WIN32
    Sleep(10);
#else
    timespec delay = { 0, 10000000 };
    nanosleep(&delay, nullptr);
#endif
}

const char *const k_tricky_arg = "spaces and \"quotes\" with \\";

int run_child(int argc, char **argv)
{
    SS_CHECK(argc == 5);
    FILE *file = std::fopen(argv[2], "w");
    SS_CHECK(file != nullptr);
    SS_CHECK(std::strcmp(argv[3], k_tricky_arg) == 0);
    SS_CHECK(std::strcmp(argv[4], "") == 0);
    const char *env = std::getenv("SS_PROCESS_TEST");
    SS_CHECK(env != nullptr && std::strcmp(env, "child value") == 0);
    std::fputs("ready\n", file);
    std::fclose(file);
    for (unsigned i = 0; i < 1000; i++) {
        pause_tick();
    }
    return 0;
}

void test_missing_program()
{
    ss_process *process = ss_process_new("ss-no-such-program-ef91ac");
    ss_process_arg(process, "ss-no-such-program-ef91ac");
    const int started = ss_process_start(process, 0);
    SS_CHECK(started == -1 || started == 0);
    // POSIX permits exec failure to be reported by child exit (notably under
    // Valgrind's spawn wrapper), rather than synchronously by posix_spawnp.
    if (started == 0) {
        for (unsigned i = 0; i < 500 && ss_process_running(process); i++) {
            pause_tick();
        }
        SS_CHECK(!ss_process_running(process));
    }
    ss_process_free(process);
}

void test_args_and_environment(const char *self)
{
    const std::string path = std::string(self) + ".child-output";
    std::remove(path.c_str());
    ss_process *process = ss_process_new(self);
    ss_process_arg(process, self);
    ss_process_arg(process, "--child");
    ss_process_arg(process, path.c_str());
    ss_process_arg(process, k_tricky_arg);
    ss_process_arg(process, "");
    ss_process_env(process, "SS_PROCESS_TEST", "child value");
    const char *before = std::getenv("SS_PROCESS_TEST");
    const std::string saved(before == nullptr ? "" : before);
    const bool had_value = before != nullptr;
    SS_CHECK(ss_process_start(process, 0) == 0);
    bool ready = false;
    for (unsigned i = 0; i < 500; i++) {
        FILE *file = std::fopen(path.c_str(), "r");
        if (file != nullptr) {
            char line[16];
            ready = std::fgets(line, sizeof(line), file) != nullptr && std::strcmp(line, "ready\n") == 0;
            std::fclose(file);
        }
        if (ready) {
            break;
        }
        pause_tick();
    }
    SS_CHECK(ready);
    SS_CHECK(ss_process_running(process));
    // The parent's environment is left untouched.
    const char *after = std::getenv("SS_PROCESS_TEST");
    SS_CHECK(had_value ? after != nullptr && saved == after : after == nullptr);
    ss_process_free(process);
    std::remove(path.c_str());
}

void test_exit_detection(const char *self)
{
    ss_process *process = ss_process_new(self);
    ss_process_arg(process, self);
    ss_process_arg(process, "--exit");
    SS_CHECK(ss_process_start(process, 0) == 0);
    for (unsigned i = 0; i < 500 && ss_process_running(process); i++) {
        pause_tick();
    }
    SS_CHECK(!ss_process_running(process));
    ss_process_free(process);
    ss_process_free(nullptr);
}

} // namespace

int main(int argc, char **argv)
{
    if (argc > 1 && std::strcmp(argv[1], "--child") == 0) {
        return run_child(argc, argv);
    }
    if (argc > 1 && std::strcmp(argv[1], "--exit") == 0) {
        return 17;
    }

    SS_RUN(test_missing_program);
    test_args_and_environment(argv[0]);
    std::printf("ok test_args_and_environment\n");
    test_exit_detection(argv[0]);
    std::printf("ok test_exit_detection\n");
    return 0;
}
