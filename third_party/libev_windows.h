/* libev's int watcher descriptors carry Winsock handles in this application.
 * Keep the same conversion for its wakeup socket pair and application I/O.
 * The default CRT descriptor conversion is incompatible with raw sockets.
 */
#include <winsock2.h>
#define EV_FD_TO_WIN32_HANDLE(fd) ((SOCKET)(unsigned int)(fd))
#define EV_WIN32_HANDLE_TO_FD(handle) ((int)(handle))
#define EV_WIN32_CLOSE_FD(fd) closesocket(EV_FD_TO_WIN32_HANDLE(fd))
