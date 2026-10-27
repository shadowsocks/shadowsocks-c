\page ss-manager ss-manager

\brief ss-server controller for multi-user management and traffic statistics

\section ss_manager_synopsis SYNOPSIS

`ss-manager [options]`

\section ss_manager_description DESCRIPTION

*shadowsocks-c* is a lightweight and secure socks5 proxy.
It is a port of the original shadowsocks created by clowwindy.
*shadowsocks-c* is written in pure C and takes advantage of libuv to
achieve both high performance and low resource consumption.

*shadowsocks-c* consists of five components.
ss-manager(1) is a controller for multi-user management and
traffic statistics, using UNIX domain socket to talk with ss-server(1).
Also, it provides a UNIX domain socket or IP based API for other software.
About the details of this API, please refer to the following `PROTOCOL`
section.

\section ss_manager_options OPTIONS

Options include all supported platform variants; restrictions are noted below.

\snippet{doc} manager.cpp cli-options

\section ss_manager_protocol PROTOCOL

ss-manager(1) provides several APIs through UDP protocol:

**Send UDP commands in the following format to the manager-address provided to ss-manager(1):**

```text
command: [JSON data]
```

**To add a port:**

```text
add: {"server_port": 8001, "password":"7cd308cc059"}
```

**To remove a port:**

```text
remove: {"server_port": 8001}
```

**To receive the traffic statistics:**

```text
ping
```

**The format of the traffic statistics:**

```text
stat: {"8001":11370}
```

There is no way to reset the traffic statistics, unless you remove the port and add it again

\section ss_manager_security SECURITY

The protocol carries no credentials, so ss-manager decides who may use it by
where commands come from:

- A UNIX domain socket (recommended) is created with mode 0600, owned by the
  user ss-manager runs as (or by the `-a` user its servers run as).
- An IP manager address must be a loopback one; any other is refused. On
  Linux a datagram is obeyed only if its source socket belongs to the same
  user, root, or the `-a` user; elsewhere any local user can reach a
  loopback address, so prefer the UNIX socket there.
- A per-server `plugin` names a program to run and is accepted only over the
  UNIX socket.

The working directory (`-D`) holds each server's configuration, with its
password, in owner-only files that are deleted when the port is removed; it
must be owned by the user running ss-manager and writable by nobody else.
`add` answers once the new ss-server is serving (or has failed), within ten
seconds.

\section ss_manager_example EXAMPLE

To use ss-manager(1), First start it and specify necessary information.

Then communicate with ss-manager(1) through UNIX Domain Socket using UDP
protocol:

```
# Start the manager. Arguments for ss-server will be passed to generated
# ss-server process(es) respectively.
ss-manager --manager-address /tmp/manager.sock --executable $(which ss-server) -s example.com -m aes-256-gcm -c /path/to/config.json

# Connect to the socket. Using netcat-openbsd as an example.
# You should use scripts or other programs for further management.
nc -Uu /tmp/manager.sock
```

After that, you may communicate with ss-manager(1) as described above in the
`PROTOCOL` section.

\section ss_manager_see_also SEE ALSO

ss-local(1),
ss-server(1),
ss-tunnel(1),
ss-redir(1),
shadowsocks-libev(8),
iptables(8),
/etc/shadowsocks-libev/config.json
