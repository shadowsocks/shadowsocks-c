\page ss-tunnel ss-tunnel

\brief shadowsocks tools for local port forwarding, C implementation

\section ss_tunnel_synopsis SYNOPSIS

`ss-tunnel [options]`

\section ss_tunnel_description DESCRIPTION

*shadowsocks-c* is a lightweight and secure socks5 proxy.
It is a port of the original shadowsocks created by clowwindy.
*shadowsocks-c* is written in pure C and takes advantage of libuv to
achieve both high performance and low resource consumption.

*shadowsocks-c* consists of five components.
ss-tunnel(1) is a tool for local port forwarding.
See `OPTIONS` section for special option needed by ss-tunnel(1).
For more information, check out shadowsocks-libev(8).

\section ss_tunnel_options OPTIONS

Options include all supported platform variants; restrictions are noted below.

\snippet{doc} tunnel.cpp cli-options

\section ss_tunnel_example EXAMPLE

ss-tunnel(1) can be used to forward DNS queries to a remote DNS server
through the shadowsocks tunnel. Here is an example:

```
# Forward local UDP port 5353 to 8.8.8.8:53 through the ss-server
ss-tunnel --server example.com:12345 --listen-port 5353 --password foobar --cipher aes-256-gcm --destination 8.8.8.8:53 --udp

# Then configure your system to use 127.0.0.1:5353 as the DNS server
dig @127.0.0.1 -p 5353 www.google.com
```

\section ss_tunnel_see_also SEE ALSO

ss-local(1),
ss-server(1),
ss-redir(1),
ss-manager(1),
shadowsocks-libev(8),
iptables(8),
/etc/shadowsocks-libev/config.json
