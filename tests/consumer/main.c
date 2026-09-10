#include <stddef.h>
#include <shadowsocks.h>
/* Force the linker to resolve the complete embedding API and its dependencies
 * without starting an unbounded event loop in this installation smoke test. */
static int (*volatile start)(profile_t) = start_ss_local_server;
static int (*volatile callback_start)(profile_t, ss_local_callback, void *) = start_ss_local_server_with_callback;
int main(void) { return start == NULL || callback_start == NULL; }
