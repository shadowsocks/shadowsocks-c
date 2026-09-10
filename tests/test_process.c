#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ss_process.h"
#ifdef _WIN32
#include <windows.h>
static void pause_tick(void) { Sleep(10); }
#else
#include <time.h>
static void pause_tick(void) { struct timespec delay = {0, 10000000}; nanosleep(&delay, NULL); }
#endif
int verbose = 0;

int
main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        assert(argc == 5);
        FILE *file = fopen(argv[2], "w");
        assert(file != NULL);
        assert(strcmp(argv[3], "spaces and \"quotes\" with \\") == 0);
        assert(strcmp(argv[4], "") == 0);
        assert(strcmp(getenv("SS_PROCESS_TEST"), "child value") == 0);
        fputs("ready\n", file);
        fclose(file);
        for (unsigned i = 0; i < 1000; i++) pause_tick();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--exit") == 0) return 17;

    struct ss_process *process = ss_process_new("ss-no-such-program-ef91ac");
    ss_process_arg(process, "ss-no-such-program-ef91ac");
    int started = ss_process_start(process, 0);
    assert(started == -1 || started == 0);
    /* POSIX permits exec failure to be reported by child exit (notably under
     * Valgrind's spawn wrapper), rather than synchronously by posix_spawnp. */
    if (started == 0) {
        for (unsigned i = 0; i < 500 && ss_process_running(process); i++) pause_tick();
        assert(!ss_process_running(process));
    }
    ss_process_free(process);

    char path[4096];
    assert(snprintf(path, sizeof(path), "%s.child-output", argv[0]) < (int)sizeof(path));
    remove(path);
    process = ss_process_new(argv[0]);
    ss_process_arg(process, argv[0]);
    ss_process_arg(process, "--child");
    ss_process_arg(process, path);
    ss_process_arg(process, "spaces and \"quotes\" with \\");
    ss_process_arg(process, "");
    ss_process_env(process, "SS_PROCESS_TEST", "child value");
    const char *before = getenv("SS_PROCESS_TEST");
    char *saved = before == NULL ? NULL : strdup(before);
    assert(ss_process_start(process, 0) == 0);
    bool ready = false;
    for (unsigned i = 0; i < 500; i++) {
        FILE *file = fopen(path, "r");
        if (file != NULL) {
            char line[16];
            ready = fgets(line, sizeof(line), file) != NULL && strcmp(line, "ready\n") == 0;
            fclose(file);
        }
        if (ready) break;
        pause_tick();
    }
    assert(ready);
    assert(ss_process_running(process));
    const char *after = getenv("SS_PROCESS_TEST");
    assert(saved == NULL ? after == NULL : after != NULL && strcmp(after, saved) == 0);
    free(saved);
    ss_process_free(process);
    remove(path);

    process = ss_process_new(argv[0]);
    ss_process_arg(process, argv[0]);
    ss_process_arg(process, "--exit");
    assert(ss_process_start(process, 0) == 0);
    for (unsigned i = 0; i < 500 && ss_process_running(process); i++) pause_tick();
    assert(!ss_process_running(process));
    ss_process_free(process);
    ss_process_free(NULL);
    return 0;
}
