\page ss-server ss-server

\brief shadowsocks server, C implementation

\section ss_server_synopsis SYNOPSIS

`ss-server [options]`

\section ss_server_description DESCRIPTION

*shadowsocks-c* is a lightweight and secure socks5 proxy.
It is a port of the original shadowsocks created by clowwindy.
*shadowsocks-c* is written in pure C and takes advantage of libuv to
achieve both high performance and low resource consumption.

*shadowsocks-c* consists of five components.
ss-server(1) runs on a remote server to provide secured tunnel service.
For more information, check out shadowsocks-libev(8).

\section ss_server_options OPTIONS

Options include all supported platform variants; restrictions are noted below.

\snippet{doc} server.cpp cli-options

\section ss_server_example EXAMPLE

It is recommended to use a config file when starting ss-server(1).

The config file is written in JSON and is easy to edit.
Check out the `SEE ALSO` section for the default path of config file.

```
# Start the ss-server
ss-server --config /etc/shadowsocks-libev/config.json
```

\section ss_server_incompatibility INCOMPATIBILITY

The config file of shadowsocks-libev(8) is slightly different from original
shadowsocks.

In order to listen to both IPv4/IPv6 address, use the following grammar in
your config json file:
```
{
"server":["::0","0.0.0.0"],
...
}
```

ss-server(1) also does not understand "port_password" field in config file.
If you want to start up multiple server instances with a single config file,
please try ss-manager tool. See ss-manager(8) for details.

\section ss_server_see_also SEE ALSO

ss-local(1),
ss-tunnel(1),
ss-redir(1),
ss-manager(1),
shadowsocks-libev(8),
iptables(8),
/etc/shadowsocks-libev/config.json
