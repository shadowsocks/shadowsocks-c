\page shadowsocks-c shadowsocks-c

\brief a lightweight and secure socks5 proxy

\section overview_synopsis SYNOPSIS

*ss-local* [options]

*ss-server* [options]

*ss-tunnel* [options]

*ss-redir* [options]

*ss-manager* [options]

*ss-nat* [options]

\section overview_description DESCRIPTION

*shadowsocks-c* is a lightweight and secure socks5 proxy.
It is a port of the original shadowsocks created by clowwindy.
*shadowsocks-c* is written in pure C and takes advantage of *libuv*
to achieve both high performance and low resource consumption.

*shadowsocks-c* consists of five components. One is ss-server(1)
that runs on a remote server to provide secured tunnel service.
ss-local(1) and ss-redir(1) are clients on your local machines to proxy
traffic(TCP/UDP or both).
ss-tunnel(1) is a tool for local port forwarding.

While ss-local(1) works as a standard socks5 proxy, ss-redir(1) works
as a transparent proxy and requires netfilter's NAT module. For more
information, check out the `EXAMPLE` section.

ss-manager(1) is a controller for multi-user management and traffic
statistics, using UNIX domain socket to talk with ss-server(1).
Also, it provides a UNIX domain socket or IP based API for other software.
About the details of this API, please refer to the `PROTOCOL` section.

\section overview_options OPTIONS

**ss-local(1)**
See this command's generated SYNOPSIS and OPTIONS for its accepted arguments.

**ss-server(1)**
See this command's generated SYNOPSIS and OPTIONS for its accepted arguments.

**ss-tunnel(1)**
See this command's generated SYNOPSIS and OPTIONS for its accepted arguments.

**ss-redir(1)**
See this command's generated SYNOPSIS and OPTIONS for its accepted arguments.

**ss-manager(1)**
See this command's generated SYNOPSIS and OPTIONS for its accepted arguments.

**ss-nat(1)**
See this command's generated SYNOPSIS and OPTIONS for its accepted arguments.

\section overview_config_file CONFIG FILE

The config file is written in JSON and easy to edit.

The config file equivalent of command line options is listed as examples below.

- `-s some.server.net`: `"server": "some.server.net"`
- `-s some.server.net -p 1234 (client)`: `"server": "some.server.net:1234"`
- `-p 1234`: `"server_port": "1234"`
- `-b 0.0.0.0`: `"local_address": "0.0.0.0"`
- `-b 10.0.0.2`: `"local_ipv4_address": "10.0.0.2"`
- `-b 2620:129:35::33`: `"local_ipv6_address": "2620:129:35::33"`
- `-l 4321`: `"local_port": "4321"`
- `-k "PasSworD"`: `"password": "PasSworD"`
- `-m "aes-256-gcm"`: `"method": "aes-256-gcm"`
- `-t 60`: `"timeout": 60`
- `-a nobody`: `"user": "nobody"`
- `--acl "/path/to/acl"`: `"acl": "/path/to/acl"`
- `--fast-open`: `"fast_open": true`
- `--reuse-port`: `"reuse_port": true`
- `--no-delay`: `"no_delay": true`
- `--max-connections 1024`: `"max_connections": 1024`
- `--max-udp-sessions 512`: `"max_udp_sessions": 512`
- `--max-dns-queries 1024`: `"max_dns_queries": 1024` (ss-server and ss-local)
- `--printable-salt`: `"printable_salt": true` (ss-local only)
- `--plugin "obfs-server"`: `"plugin": "obfs-server"`
- `--plugin-opts "obfs=http"`: `"plugin_opts": "obfs=http"`
- `-6`: `"ipv6_first": true`
- `-n 1024`: `"nofile": 1024`
- `-d "8.8.8.8"`: `"nameserver": "8.8.8.8"`
- `-L "somedns.net:53"`: `"tunnel_address": "somedns.net:53"`
- `-u`: `"mode": "tcp_and_udp"`
- `-U`: `"mode": "udp_only"`
- `no "-u" nor "-U" options (default)`: `"mode": "tcp_only"`
- `-T`: `"tcp_tproxy": true`
- `(only in ss-manager's config)`: `"port_password": {"1234":"PasSworD"}`
 |
\section overview_example EXAMPLE

`ss-redir` requires netfilter's NAT function. Here is an example:

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
ip rule add fwmark 0x01/0x01 table 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A SHADOWSOCKS -p udp --dport 53 -j TPROXY --on-port 12345 --tproxy-mark 0x01/0x01

# Apply the rules
iptables -t nat -A PREROUTING -p tcp -j SHADOWSOCKS
iptables -t mangle -A PREROUTING -j SHADOWSOCKS

# Start the shadowsocks-redir
ss-redir -u -c /etc/config/shadowsocks.json -f /var/run/shadowsocks.pid
```

\section overview_protocol PROTOCOL

**ss-manager(1) provides several APIs through UDP protocol**

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

**To receive a pong:**

```text
ping
```

**Then ss-manager(1) will send back the traffic statistics:**

```text
stat: {"8001":11370}
```

\section overview_see_also SEE ALSO

ss-local(1),
ss-server(1),
ss-tunnel(1),
ss-redir(1),
ss-manager(1),
iptables(8),
/etc/shadowsocks-libev/config.json
