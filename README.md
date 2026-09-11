# shadowsocks-c

[![Build](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/build.yml) [![Tests](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/tests.yml) [![Portability](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/portability.yml/badge.svg?branch=master)](https://github.com/shadowsocks/shadowsocks-c/actions/workflows/portability.yml)

## Intro

[shadowsocks-c](https://shadowsocks.org) is a lightweight secured SOCKS5
proxy for embedded devices and low-end boxes.

It is a port of [Shadowsocks](https://github.com/shadowsocks/shadowsocks)
created by [@clowwindy](https://github.com/clowwindy), and maintained by
[@madeye](https://github.com/madeye) and [@linusyang](https://github.com/linusyang).

Current version: 3.3.6 | [Changelog](debian/changelog)

## Project history and rename

This repository began as **shadowsocks-libev**, the lightweight C implementation
of Shadowsocks built around the libev event loop. It later entered a bug-fix-only
maintenance phase, with new development directed toward
[shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust).

In September 2026, the C implementation was modernized with a focus on
self-contained builds and portability. [The build modernization](https://github.com/shadowsocks/shadowsocks-c/pull/3050)
bundled pinned dependency sources, removed several external dependencies, and
added static-build validation across platforms.
[The subsequent migration](https://github.com/shadowsocks/shadowsocks-c/pull/3051)
replaced libev with libuv, added Windows IOCP and macOS kqueue support, expanded
asynchronous runtime DNS coverage, and strengthened CI lint checks.

The project and GitHub repository were renamed **shadowsocks-c** to reflect its
continuing identity as a pure C implementation. This repository retains the
shadowsocks-libev commit history and releases. The canonical repository is now
[shadowsocks/shadowsocks-c](https://github.com/shadowsocks/shadowsocks-c).

### Compatibility with shadowsocks-libev

- Commands such as `ss-local` and `ss-server`, the `shadowsocks.h` API, and the
  embedding library ABI remain compatible.
- New builds provide `libshadowsocks-c` and the CMake/pkg-config package
  `shadowsocks-c`. Legacy library filenames and the `shadowsocks-libev` package
  lookup name remain available as compatibility aliases.
- Existing configuration paths, distribution package names, and service names
  are retained. References to `shadowsocks-libev` in the installation examples
  below refer to those existing integrations.

See [the modernization notes](docs/modernization.md) for build options and
platform support, and [the performance measurements](docs/performance.md) for
measured tradeoffs.

## Features

shadowsocks-c is written in pure C and depends on [libuv](https://libuv.org/). It's designed
to be a lightweight implementation of shadowsocks protocol, in order to keep the resource usage as low as possible.

For a full list of feature comparison between different versions of shadowsocks,
refer to the [Wiki page](https://github.com/shadowsocks/shadowsocks/wiki/Feature-Comparison-across-Different-Versions).

## Quick Start

### Docker (recommended)

Docker is the recommended way to run a server. The image contains the bundled,
fully static C binaries and supports Linux AMD64 and ARM64, including Linux
containers under Docker Desktop on macOS and Windows.

Create `config.json` and replace the example password with your own:

```json
{
  "server": "0.0.0.0",
  "server_port": 8388,
  "password": "replace-with-a-long-random-password",
  "method": "aes-256-gcm",
  "mode": "tcp_and_udp"
}
```

In a POSIX shell, start the server with the configuration mounted read-only:

```sh
docker pull ghcr.io/shadowsocks/shadowsocks-c:latest
docker run -d --name shadowsocks-c --restart unless-stopped \
  --user "$(id -u):$(id -g)" --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -p 8388:8388/tcp -p 8388:8388/udp \
  --mount type=bind,src="$PWD/config.json",dst=/etc/shadowsocks-c/config.json,readonly \
  ghcr.io/shadowsocks/shadowsocks-c:latest
```

Using your user ID lets the container read a configuration file owned by you.
View logs with `docker logs shadowsocks-c`; stop it with `docker stop shadowsocks-c`.
Configure your Shadowsocks client with the server address, port, password and
method above.

`latest` follows `master`; version tags and `sha-<full-commit>` tags identify
specific published builds. If the registry image is not yet available, build it
from this checkout with the same name, then run the command above without pulling:

```sh
docker build -f docker/static/Dockerfile --target runtime \
  -t ghcr.io/shadowsocks/shadowsocks-c:latest .
```

See [Docker image details](docker/static/README.md) for publishing, updates,
client mode and build options. Existing Snap packages still use the
`shadowsocks-libev` name and may predate this modernization.

## Installation

### Distribution-specific guide

- [Debian & Ubuntu](#debian--ubuntu)
    + [Install from repository](#install-from-repository-not-recommended)
    + [Build deb package from source](#build-deb-package-from-source)
    + [Configure and start the service](#configure-and-start-the-service)
- [Fedora & RHEL](#fedora--rhel)
    + [Build from source with centos](#build-from-source-with-centos)
- [Archlinux & Manjaro](#archlinux--manjaro)
- [NixOS](#nixos)
- [Nix](#nix)
- [Directly build and install on UNIX-like system](#linux)
- [FreeBSD](#freebsd)
    + [Install](#install)
    + [Configuration](#configuration)
    + [Run](#run)
    + [Run as client](#run-as-client)
- [OpenWRT](#openwrt)
- [macOS](#macos)
- [Windows (MinGW)](#windows-mingw)
- [Docker](#docker)

* * *

### Build from source (CMake)

The default build uses pinned sources included in this repository. It needs a
C11 compiler, CMake 3.20+, and Make or Ninja. No Git submodules, dependency
package installations, or network access are needed for configuration/build.
Python is used only by integration tests; documentation generation is optional.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build -L 'unit|vendor' --output-on-failure
cmake --install build --prefix /your/install/prefix
```

Programs are in `build/bin/`. Bundled binaries link to platform runtime
libraries; they do not require separately installed third-party libraries.

For a smaller build, use `-DSS_MINIMAL=ON`. It excludes PCRE2 regex, plugin
subprocesses, the manager, and legacy stream ciphers. Minimal ACLs support
IPv4/IPv6 CIDRs, `full:example.com` for exact domains, and
`suffix:example.com` for the apex and subdomains. Literal matches ignore ASCII
case and respect label boundaries. Unsupported regex rules are rejected.

Distribution packages can use `-DSS_DEPENDENCY_MODE=system -DWITH_STATIC=OFF`
with libuv, c-ares, libsodium, Mbed TLS 3.x, and PCRE2 development packages.
Use `-DCMAKE_PREFIX_PATH=/opt/homebrew/opt/mbedtls@3` when needed on macOS.

| Option | Default | Purpose |
|---|---|---|
| `SS_DEPENDENCY_MODE` | `bundled` | `bundled` sources or `system` libraries |
| `WITH_STATIC` | `ON` | Link dependency archives; system mode also supports shared dependencies |
| `SS_BUILD_EXECUTABLES` | `ON` | Command-line tools |
| `SS_BUILD_STATIC_LIBRARY` | `ON` | Static embedding library with installed dependency archives |
| `SS_BUILD_SHARED_LIBRARY` | `ON` | Shared embedding library |
| `SS_MINIMAL` | `OFF` | Disable regex, plugins, manager, and legacy stream ciphers |
| `SS_ENABLE_REGEX` / `SS_ENABLE_PLUGINS` / `SS_ENABLE_LEGACY` | `ON` | Individual compatibility features |
| `WITH_DOC_MAN` / `WITH_DOC_HTML` | `OFF` | Generate documentation (requires asciidoc; man pages also need xmlto) |
| `SS_INSTALL_TOOLS` | `OFF` | Install platform shell helpers |
| `ENABLE_SANITIZERS` | `OFF` | AddressSanitizer and UndefinedBehaviorSanitizer |
| `ENABLE_CONNMARKTOS` / `ENABLE_NFTABLES` | `OFF` | Optional Linux firewall integrations |

CMake consumers can use `find_package(shadowsocks-c CONFIG REQUIRED)` and
link `shadowsocks::static`, `shadowsocks::shared`, or `shadowsocks::shadowsocks`
(which prefers the shared library when installed). A pkg-config file is also
installed. Dependency provenance and update instructions are in
[third_party/README.md](third_party/README.md); modernization progress and
validation limits are tracked in [docs/modernization.md](docs/modernization.md).

### Debian & Ubuntu

#### Distribution packages

Package availability and versions depend on the distribution release; packaged
versions can differ from this source branch.

```bash
sudo apt update
sudo apt install shadowsocks-libev
```

#### Build deb package from source

Install the build dependencies listed in `debian/control`, then build the
packages from this checkout:

```bash
dpkg-buildpackage -b -us -uc
```

Debian packaging explicitly uses system libraries. For a bundled build without
library development packages, use the [CMake instructions](#build-from-source-cmake).

#### Configure and start the service

```
# Edit the configuration file
sudo vim /etc/shadowsocks-libev/config.json

# Edit the default configuration for debian
sudo vim /etc/default/shadowsocks-libev

# Start the service
sudo /etc/init.d/shadowsocks-libev start    # for sysvinit, or
sudo systemctl start shadowsocks-libev      # for systemd
```

### Fedora & RHEL

Use the bundled CMake build above with a C11 compiler, CMake 3.20+ and Make
or Ninja. Older distribution toolchains may need upgrading. Autotools, gettext
and separately installed crypto/event/DNS development libraries are not required
for bundled mode.

### Archlinux & Manjaro

```bash
sudo pacman -S shadowsocks-libev
```

Please refer to downstream [PKGBUILD](https://github.com/archlinux/svntogit-community/blob/packages/shadowsocks-libev/trunk/PKGBUILD)
script for extra modifications and distribution-specific bugs.

### NixOS

```bash
nix-env -iA nixos.shadowsocks-libev
```

### Nix

```bash
nix-env -iA nixpkgs.shadowsocks-libev
```

### Linux

The default bundled build needs only a C11 compiler, CMake 3.20+ and Make
or Ninja. For example, on Debian/Ubuntu:

```bash
sudo apt-get install --no-install-recommends build-essential cmake
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build -L 'unit|vendor' --output-on-failure
sudo cmake --install build
```

Distribution packagers can install `libpcre2-dev libuv1-dev libc-ares-dev
libmbedtls-dev libsodium-dev` and select `-DSS_DEPENDENCY_MODE=system
-DWITH_STATIC=OFF`. Documentation additionally needs asciidoc and xmlto.

### FreeBSD
#### Install
Shadowsocks-libev is available in FreeBSD Ports Collection. You can install it in either way, `pkg` or `ports`.

**pkg (recommended)**

```bash
pkg install shadowsocks-libev
```

**ports**

```bash
cd /usr/ports/net/shadowsocks-libev
make install
```

#### Configuration
Edit your `config.json` file. By default, it's located in `/usr/local/etc/shadowsocks-libev`.

To enable shadowsocks-libev, add the following rc variable to your `/etc/rc.conf` file:

```
shadowsocks_libev_enable="YES"
```

#### Run

Start the Shadowsocks server:

```bash
service shadowsocks_libev start
```

#### Run as client
By default, shadowsocks-libev is running as a server in FreeBSD. If you would like to start shadowsocks-libev in client mode, you can modify the rc script (`/usr/local/etc/rc.d/shadowsocks_libev`) manually.

```
# modify the following line from "ss-server" to "ss-local"
command="/usr/local/bin/ss-local"
```

Note that is simply a workaround, each time you upgrade the port your changes will be overwritten by the new version.

### OpenWRT

The OpenWRT project is maintained here:
[openwrt-shadowsocks](https://github.com/shadowsocks/openwrt-shadowsocks).

### macOS

Use the bundled CMake instructions above with Xcode Command Line Tools and
CMake. The bundled executables require no Homebrew runtime libraries.
For system mode, use Mbed TLS 3 and point `CMAKE_PREFIX_PATH` at its prefix.

### Windows (MinGW)

In an MSYS2 UCRT64 shell, install the toolchain and build native Windows programs:

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja
cmake -S . -B build -G Ninja
cmake --build build --parallel
ctest --test-dir build -L 'unit|vendor' --output-on-failure
```

Unix hosts with Zig installed can cross-compile without a separate MinGW SDK:

```bash
cmake -S . -B build-windows -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/zig-windows.cmake
cmake --build build-windows --parallel
```

Cross-compilation does not run Windows tests. The portability workflow runs
native UCRT64 tests and TCP/UDP relay checks on Windows. Bundled mode is required
with a bundled libuv IOCP backend. MSVC remains a
separate, unsupported milestone; configuration reports this explicitly.
The historical Autotools scripts in `docker/mingw` are superseded by this build.

### Docker

Use the [recommended Docker installation](#docker-recommended) above.
The image is `ghcr.io/shadowsocks/shadowsocks-c`; it accepts a JSON configuration
file or the normal `ss-server` arguments. The historical `PASSWORD` environment
variable wrapper belongs to the older Docker Hub image and is not used here.
See [image and build details](docker/static/README.md).

## Usage

For a detailed and complete list of all supported arguments,
you may refer to the man pages of the applications, respectively.

    ss-[local|redir|server|tunnel|manager]

       -s <server_host>           Host name or IP address of your remote server.

       -p <server_port>           Port number of your remote server.

       -l <local_port>            Port number of your local server.

       -k <password>              Password of your remote server.

       -m <encrypt_method>        Encrypt method:
                                  2022-blake3-aes-128-gcm,
                                  2022-blake3-aes-256-gcm,
                                  2022-blake3-chacha20-poly1305,
                                  rc4-md5,
                                  aes-128-gcm, aes-192-gcm, aes-256-gcm,
                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,
                                  aes-128-ctr, aes-192-ctr, aes-256-ctr,
                                  camellia-128-cfb, camellia-192-cfb,
                                  camellia-256-cfb, bf-cfb,
                                  chacha20-ietf-poly1305,
                                  xchacha20-ietf-poly1305,
                                  salsa20, chacha20 and chacha20-ietf.
                                  The default cipher is chacha20-ietf-poly1305.

                                  The 2022-blake3-* ciphers implement
                                  Shadowsocks 2022 (SIP022) and are the
                                  recommended choice. They take a
                                  base64-encoded pre-shared key of exactly
                                  the cipher's key size via -k, not a
                                  password: generate one with
                                  `openssl rand -base64 32` (or 16 for
                                  2022-blake3-aes-128-gcm).

       [--server-url <ss_url>]    Take the server address, port, cipher,
                                  password and SIP003 plugin from a single
                                  ss:// URL (SIP002 or the legacy form).
                                  ss-local only. Options given later on the
                                  command line override the URL's values.

       [-a <user>]                Run as another user.

       [-f <pid_file>]            The file path to store pid.

       [-t <timeout>]             Socket timeout in seconds.

       [-c <config_file>]         The path to config file.

       [-n <number>]              Max number of open files.

       [-i <interface>]           Network interface to bind.
                                  (not available in redir mode)

       [-b <local_address>]       Local address to bind.
                                  For servers: Specify the local address to use 
                                  while this server is making outbound 
                                  connections to remote servers on behalf of the
                                  clients.
                                  For clients: Specify the local address to use 
                                  while this client is making outbound 
                                  connections to the server.

       [-u]                       Enable UDP relay.
                                  (TPROXY is required in redir mode)

       [-U]                       Enable UDP relay and disable TCP relay.
                                  (not available in local mode)

       [-T]                       Use tproxy instead of redirect. (for tcp)
                                  (only available in redir mode)

       [-L <addr>:<port>]         Destination server address and port
                                  for local port forwarding.
                                  (only available in tunnel mode)

       [-6]                       Resolve hostname to IPv6 address first.

       [-d <addr>]                Name servers for internal DNS resolver.
                                  (only available in server mode)

       [--reuse-port]             Enable port reuse.

       [--fast-open]              Enable TCP fast open.
                                  with Linux kernel > 3.7.0.
                                  (only available in local and server mode)

       [--acl <acl_file>]         Path to ACL (Access Control List).
                                  (only available in local and server mode)

       [--manager-address <addr>] UNIX domain socket address.
                                  (only available in server and manager mode)

       [--mtu <MTU>]              MTU of your network interface.

       [--mptcp]                  Enable Multipath TCP on MPTCP Kernel.

       [--no-delay]               Enable TCP_NODELAY.

       [--executable <path>]      Path to the executable of ss-server.
                                  (only available in manager mode)

       [-D <path>]                Path to the working directory of ss-manager.
                                  (only available in manager mode)

       [--key <key_in_base64>]    Key of your remote server.

       [--plugin <name>]          Enable SIP003 plugin. (Experimental)

       [--plugin-opts <options>]  Set SIP003 plugin options. (Experimental)

       [-v]                       Verbose mode.

## Helper Scripts

### ss-setup

`ss-setup` is an interactive TUI (text user interface) tool for setting up shadowsocks-libev server and client configurations. It uses `whiptail` or `dialog` for the menu interface.

It is installed automatically by `make install` and can also be run directly from `scripts/ss-setup.sh`.

**Prerequisites:** `whiptail` or `dialog`, `openssl` (optional, for password generation)

#### Server setup (with systemd service)

Run as root for full functionality (config + systemd service installation):

```bash
sudo ss-setup
```

This launches an interactive menu that walks you through:
1. Choosing a config instance name
2. Setting the listen address and port (manual or random high port)
3. Selecting an AEAD cipher (chacha20-ietf-poly1305, aes-256-gcm, etc.)
4. Generating or entering a password
5. Configuring timeout, network mode (TCP/UDP), and TCP Fast Open
6. Optionally selecting a SIP003 plugin
7. Installing and starting a systemd service

The config is saved to `/etc/shadowsocks-libev/<name>.json` and a systemd template service `shadowsocks-libev-server@<name>.service` is created.

At the end, it displays a `ss://` URI you can import into clients.

#### Client config generation

Select "Generate ss-local client config" from the main menu. The wizard prompts for the remote server address, port, cipher, password, and local SOCKS5 port, then writes a JSON config:

```bash
# Run without root to generate config in the current directory
ss-setup
# Select: client -> fill in server details -> save

# Then start the client
ss-local -c ~/ss-client.json
```

#### Config-only mode (non-root)

When run without root, `ss-setup` skips service installation and plugin management, but still generates config files in the current directory:

```bash
ss-setup
# Config saved to ./config.json (in current directory)
# Start manually:
ss-server -c ./config.json
```

#### Service management

From the main menu, select "Manage running services" to start, stop, restart, enable/disable, or view logs for any configured instance:

```
sudo ss-setup
# Select: service -> pick instance -> start/stop/restart/logs
```

#### Plugin installation

Select "Install a SIP003 plugin" from the main menu (requires root). Supports automatic download of:
- simple-obfs (build from source or package manager)
- v2ray-plugin (GitHub release)
- xray-plugin (GitHub release)
- kcptun (GitHub release)
- Custom plugin binary

### ss-nat

`ss-nat` is a helper script that sets up iptables NAT rules for `ss-redir` to provide transparent TCP/UDP redirection. Enable `-DSS_INSTALL_TOOLS=ON` to install it on Linux.

**Prerequisites:** Linux with `iptables`, `ipset`, and optionally TPROXY kernel module for UDP

#### Basic usage (TCP redirect)

```bash
# Start ss-redir first
ss-redir -s YOUR_SERVER_IP -p 8388 -l 1080 -k PASSWORD -m chacha20-ietf-poly1305 -u

# Set up NAT rules to redirect TCP traffic through ss-redir
sudo ss-nat -s YOUR_SERVER_IP -l 1080
```

#### Enable UDP relay with TPROXY

```bash
sudo ss-nat -s YOUR_SERVER_IP -l 1080 -u
```

#### Apply rules to OUTPUT chain (proxy the local machine itself)

```bash
sudo ss-nat -s YOUR_SERVER_IP -l 1080 -u -o
```

#### Use separate TCP/UDP servers

```bash
sudo ss-nat -s TCP_SERVER_IP -l 1080 -S UDP_SERVER_IP -L 1080 -U
```

#### Bypass specific WAN IPs

```bash
sudo ss-nat -s YOUR_SERVER_IP -l 1080 -b "1.2.3.4 5.6.7.8"
```

#### Use a bypass IP list file

```bash
# Create a file with one IP/CIDR per line
echo "1.2.3.0/24" > /etc/ss-bypass.list
echo "5.6.7.0/24" >> /etc/ss-bypass.list

sudo ss-nat -s YOUR_SERVER_IP -l 1080 -i /etc/ss-bypass.list
```

#### LAN access control

```bash
# Whitelist mode: only proxy traffic from these LAN IPs
sudo ss-nat -s YOUR_SERVER_IP -l 1080 -a "w192.168.1.10 192.168.1.20"

# Blacklist mode: proxy all LAN traffic except these IPs
sudo ss-nat -s YOUR_SERVER_IP -l 1080 -a "b192.168.1.100"
```

#### Flush all rules

```bash
sudo ss-nat -f
```

#### Complete example: transparent proxy gateway

Set up a Linux box as a transparent proxy gateway for the entire LAN:

```bash
# 1. Start ss-redir with UDP relay
ss-redir -s YOUR_SERVER_IP -p 8388 -l 1080 -k PASSWORD \
    -m chacha20-ietf-poly1305 -u -f /var/run/ss-redir.pid

# 2. Set up NAT rules (TCP + UDP, apply to local OUTPUT too)
sudo ss-nat -s YOUR_SERVER_IP -l 1080 -u -o -I eth0

# 3. Point other devices' default gateway to this machine's LAN IP
#    and set their DNS to a public resolver (e.g., 1.1.1.1 or 8.8.8.8)

# To tear down:
sudo ss-nat -f
```

## Transparent proxy (manual iptables)

The latest shadowsocks-libev has provided a *redir* mode. You can configure your Linux-based box or router to proxy all TCP traffic transparently, which is handy if you use an OpenWRT-powered router.

Note: For most use cases, [`ss-nat`](#ss-nat) above is simpler than writing iptables rules manually.

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

## Transparent proxy (pure tproxy)

Executing this script on the linux host can proxy all outgoing traffic of this machine (except the traffic sent to the reserved address). Other hosts under the same LAN can also change their default gateway to the ip of this linux host (at the same time change the dns server to 1.1.1.1 or 8.8.8.8, etc.) to proxy their outgoing traffic.

> Of course, the ipv6 proxy is similar, just change `iptables` to `ip6tables`, `ip` to `ip -6`, `127.0.0.1` to `::1`, and other details.

```shell
#!/bin/bash

start_ssredir() {
    # please modify MyIP, MyPort, etc.
    (ss-redir -s MyIP -p MyPort -m MyMethod -k MyPasswd -b 127.0.0.1 -l 60080 --no-delay -u -T -v </dev/null &>>/var/log/ss-redir.log &)
}

stop_ssredir() {
    kill -9 $(pidof ss-redir) &>/dev/null
}

start_iptables() {
    ##################### SSREDIR #####################
    iptables -t mangle -N SSREDIR

    # connection-mark -> packet-mark
    iptables -t mangle -A SSREDIR -j CONNMARK --restore-mark
    iptables -t mangle -A SSREDIR -m mark --mark 0x2333 -j RETURN

    # please modify MyIP, MyPort, etc.
    # ignore traffic sent to ss-server
    iptables -t mangle -A SSREDIR -p tcp -d MyIP --dport MyPort -j RETURN
    iptables -t mangle -A SSREDIR -p udp -d MyIP --dport MyPort -j RETURN

    # ignore traffic sent to reserved addresses
    iptables -t mangle -A SSREDIR -d 0.0.0.0/8          -j RETURN
    iptables -t mangle -A SSREDIR -d 10.0.0.0/8         -j RETURN
    iptables -t mangle -A SSREDIR -d 100.64.0.0/10      -j RETURN
    iptables -t mangle -A SSREDIR -d 127.0.0.0/8        -j RETURN
    iptables -t mangle -A SSREDIR -d 169.254.0.0/16     -j RETURN
    iptables -t mangle -A SSREDIR -d 172.16.0.0/12      -j RETURN
    iptables -t mangle -A SSREDIR -d 192.0.0.0/24       -j RETURN
    iptables -t mangle -A SSREDIR -d 192.0.2.0/24       -j RETURN
    iptables -t mangle -A SSREDIR -d 192.88.99.0/24     -j RETURN
    iptables -t mangle -A SSREDIR -d 192.168.0.0/16     -j RETURN
    iptables -t mangle -A SSREDIR -d 198.18.0.0/15      -j RETURN
    iptables -t mangle -A SSREDIR -d 198.51.100.0/24    -j RETURN
    iptables -t mangle -A SSREDIR -d 203.0.113.0/24     -j RETURN
    iptables -t mangle -A SSREDIR -d 224.0.0.0/4        -j RETURN
    iptables -t mangle -A SSREDIR -d 240.0.0.0/4        -j RETURN
    iptables -t mangle -A SSREDIR -d 255.255.255.255/32 -j RETURN

    # mark the first packet of the connection
    iptables -t mangle -A SSREDIR -p tcp --syn                      -j MARK --set-mark 0x2333
    iptables -t mangle -A SSREDIR -p udp -m conntrack --ctstate NEW -j MARK --set-mark 0x2333

    # packet-mark -> connection-mark
    iptables -t mangle -A SSREDIR -j CONNMARK --save-mark

    ##################### OUTPUT #####################
    # proxy the outgoing traffic from this machine
    iptables -t mangle -A OUTPUT -p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    iptables -t mangle -A OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR

    ##################### PREROUTING #####################
    # proxy traffic passing through this machine (other->other)
    iptables -t mangle -A PREROUTING -p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    iptables -t mangle -A PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR

    # hand over the marked package to TPROXY for processing
    iptables -t mangle -A PREROUTING -p tcp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080
    iptables -t mangle -A PREROUTING -p udp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080
}

stop_iptables() {
    ##################### PREROUTING #####################
    iptables -t mangle -D PREROUTING -p tcp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080 &>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 60080 &>/dev/null

    iptables -t mangle -D PREROUTING -p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null

    ##################### OUTPUT #####################
    iptables -t mangle -D OUTPUT -p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
    iptables -t mangle -D OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null

    ##################### SSREDIR #####################
    iptables -t mangle -F SSREDIR &>/dev/null
    iptables -t mangle -X SSREDIR &>/dev/null
}

start_iproute2() {
    ip route add local default dev lo table 100
    ip rule  add fwmark 0x2333        table 100
}

stop_iproute2() {
    ip rule  del   table 100 &>/dev/null
    ip route flush table 100 &>/dev/null
}

start_resolvconf() {
    # or nameserver 8.8.8.8, etc.
    echo "nameserver 1.1.1.1" >/etc/resolv.conf
}

stop_resolvconf() {
    echo "nameserver 114.114.114.114" >/etc/resolv.conf
}

start() {
    echo "start ..."
    start_ssredir
    start_iptables
    start_iproute2
    start_resolvconf
    echo "start end"
}

stop() {
    echo "stop ..."
    stop_resolvconf
    stop_iproute2
    stop_iptables
    stop_ssredir
    echo "stop end"
}

restart() {
    stop
    sleep 1
    start
}

main() {
    if [ $# -eq 0 ]; then
        echo "usage: $0 start|stop|restart ..."
        return 1
    fi

    for funcname in "$@"; do
        if [ "$(type -t $funcname)" != 'function' ]; then
            echo "'$funcname' not a shell function"
            return 1
        fi
    done

    for funcname in "$@"; do
        $funcname
    done
    return 0
}
main "$@"
```

## Security Tips

For any public server, to avoid users accessing localhost of your server, please add `--acl acl/server_block_local.acl` to the command line.

Although shadowsocks-libev can handle thousands of concurrent connections nicely, we still recommend
setting up your server's firewall rules to limit connections from each user:

    # Up to 32 connections are enough for normal usage
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKS_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## License

```
Copyright: 2013-2015, Clow Windy <clowwindy42@gmail.com>
           2013-2018, Max Lv <max.c.lv@gmail.com>
           2014, Linus Yang <linusyang@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```
