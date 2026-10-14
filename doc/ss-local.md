\page ss-local ss-local

\brief shadowsocks client as socks5 proxy, C implementation

\section ss_local_synopsis SYNOPSIS

`ss-local [options]`

\section ss_local_description DESCRIPTION

*shadowsocks-c* is a lightweight and secure socks5 proxy.
It is a port of the original shadowsocks created by clowwindy.
*shadowsocks-c* is written in pure C and takes advantage of libuv to
achieve both high performance and low resource consumption.

*shadowsocks-c* consists of five components. ss-local(1) works as a standard
socks5 proxy on local machines to proxy TCP traffic.
For more information, check out shadowsocks-libev(8).

\section ss_local_options OPTIONS

Options include all supported platform variants; restrictions are noted below.

\snippet{doc} local.cpp cli-options

\section ss_local_example EXAMPLE

ss-local(1) can be started from command line and run in foreground.
Here is an example:
```
# Start ss-local with given parameters
ss-local --server example.com:12345 --listen-port 1080 --password foobar --cipher aes-256-gcm
```

\section ss_local_see_also SEE ALSO

ss-server(1),
ss-tunnel(1),
ss-redir(1),
ss-manager(1),
shadowsocks-libev(8),
iptables(8),
/etc/shadowsocks-libev/config.json
