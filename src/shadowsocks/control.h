/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SHADOWSOCKS_CONTROL_H
#define SHADOWSOCKS_CONTROL_H

/*
 * Run ss-local inside an application: start it on a thread owned by the
 * library, stop it from anywhere, and wait for it to finish.
 *
 * The server state is process-wide, so one instance runs at a time; a
 * second ss_local_start() while one is running fails with EBUSY.
 */

#include <shadowsocks.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ss_local_handle ss_local_handle;

/*
 * Copy the profile and start serving on a new thread. `callback` (may be
 * NULL) runs on that thread once the sockets are listening, as with
 * start_ss_local_server_with_callback(). Returns 0 and sets *handle, or an
 * errno value: EBUSY, EINVAL or ENOMEM.
 */
int ss_local_start(const profile_t *profile, ss_local_callback callback, void *udata, ss_local_handle **handle);

/* Ask the server to stop. Safe from any thread (not from a signal
 * handler), and harmless once it has stopped. */
void ss_local_stop(ss_local_handle *handle);

/* Wait for the server thread and return what the server returned (0 after
 * a requested stop). Later or concurrent calls return the same value. */
int ss_local_wait(ss_local_handle *handle);

/* Release the handle, stopping and waiting for the server first if needed.
 * The handle is freed: no other thread may still be calling stop or wait
 * on it, or call them afterwards. */
void ss_local_destroy(ss_local_handle *handle);

#ifdef __cplusplus
}
#endif

#endif /* SHADOWSOCKS_CONTROL_H */
