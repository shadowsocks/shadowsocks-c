\page ss-redir ss-redir

\brief shadowsocks client as transparent proxy, C implementation

\section ss_redir_synopsis SYNOPSIS

`ss-redir [options]`

\section ss_redir_description DESCRIPTION

*shadowsocks-c* is a lightweight and secure socks5 proxy.
It is a port of the original shadowsocks created by clowwindy.
*shadowsocks-c* is written in pure C and takes advantage of libuv to
achieve both high performance and low resource consumption.

*shadowsocks-c* consists of five components.
ss-redir(1) works as a transparent proxy on local machines to proxy TCP
traffic and requires netfilter's NAT module.
For more information, check out shadowsocks-libev(8) and the following
`EXAMPLE` section.

\section ss_redir_options OPTIONS

Options include all supported platform variants; restrictions are noted below.

\snippet{doc} redir.cpp cli-options

\section ss_redir_example EXAMPLE

ss-redir requires netfilter's NAT function. Here is an example:

```
# Create new chain
iptables -t nat -N SHADOWSOCKS
iptables -t mangle -N SHADOWSOCKS

# Ignore your shadowsocks server's addresses
# It's very IMPORTANT, just be careful.
iptables -t nat -A SHADOWSOCKS -d 123.123.123.123 -j RETURN

# Ignore LANs and any other addresses you'd like to bypass the proxy
# See Wikipedia and RFC5735 for full list of reserved networks.
# See ashi009/bestroutetb for a highly optimized CHN route list.
iptables -t nat -A SHADOWSOCKS -d 0.0.0.0/8 -j RETURN
iptables -t nat -A SHADOWSOCKS -d 10.0.0.0/8 -j RETURN
iptables -t nat -A SHADOWSOCKS -d 127.0.0.0/8 -j RETURN
iptables -t nat -A SHADOWSOCKS -d 169.254.0.0/16 -j RETURN
iptables -t nat -A SHADOWSOCKS -d 172.16.0.0/12 -j RETURN
iptables -t nat -A SHADOWSOCKS -d 192.168.0.0/16 -j RETURN
iptables -t nat -A SHADOWSOCKS -d 224.0.0.0/4 -j RETURN
iptables -t nat -A SHADOWSOCKS -d 240.0.0.0/4 -j RETURN

# Anything else should be redirected to shadowsocks's local port
iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports 12345

# Add any UDP rules
ip route add local default dev lo table 100
ip rule add fwmark 1 lookup 100
iptables -t mangle -A SHADOWSOCKS -p udp --dport 53 -j TPROXY --on-port 12345 --tproxy-mark 0x01/0x01

# Apply the rules
iptables -t nat -A PREROUTING -p tcp -j SHADOWSOCKS
iptables -t mangle -A PREROUTING -j SHADOWSOCKS

# Start the shadowsocks-redir
ss-redir -u -c /etc/config/shadowsocks.json -f /var/run/shadowsocks.pid
```

\section ss_redir_see_also SEE ALSO

ss-local(1),
ss-server(1),
ss-tunnel(1),
ss-manager(1),
shadowsocks-libev(8),
iptables(8),
/etc/shadowsocks-libev/config.json
