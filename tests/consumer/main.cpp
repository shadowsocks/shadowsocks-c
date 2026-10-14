// C++ consumer of the installed headers: the RAII wrapper over the C
// control API, without starting a server.
#include <shadowsocks/shadowsocks.hpp>

int main()
{
    shadowsocks::LocalServer server;
    static int (*volatile start)(const profile_t *, ss_local_callback, void *, ss_local_handle **) = ss_local_start;
    return server.running() || start == nullptr;
}
