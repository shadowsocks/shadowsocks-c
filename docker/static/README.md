# Docker image and static Linux builds

Use `ghcr.io/shadowsocks/shadowsocks-c` for Linux AMD64 or ARM64. The
[README quick start](../../README.md#docker-recommended) shows server configuration,
TCP/UDP port mapping and a read-only configuration mount. Docker Desktop runs
these Linux images on macOS and Windows.

The default entrypoint is `ss-server -c /etc/shadowsocks-c/config.json`.
Passing arguments overrides that default configuration argument. The image runs
as UID/GID `65532:65532` unless `--user` is supplied; the mounted file must be
readable by that user. Logs go to standard output/error. No writable filesystem
is required for normal server operation.

To update a running server, pull the desired tag, remove the old container with
`docker rm -f shadowsocks-c`, and repeat the quick-start run command. The host
configuration file is preserved. `latest` tracks `master`; choose a published
version tag or `sha-<full-commit>` to pin a build.

For a SOCKS5 client, override the entrypoint with
`--entrypoint /usr/local/bin/ss-local`, supply a client configuration using `-c`,
and publish the configured local TCP/UDP port. Bind the local listener to
`0.0.0.0` inside the container and restrict its host mapping to loopback, such as
`-p 127.0.0.1:1080:1080/tcp -p 127.0.0.1:1080:1080/udp`.

## Publishing

`.github/workflows/docker.yml` builds each architecture on a native runner and
exercises the actual scratch server/client containers with concurrent TCP,
hostname resolution, UDP and clean shutdown. PRs run these checks without
publishing. Pushes to `master` publish `latest` and `sha-<full-commit>`; `v*`
version tags publish the version without the leading `v` and the commit tag.
The multi-platform tag is assembled only after both architecture tests pass.
Publishing uses the repository's `GITHUB_TOKEN` with `packages: write`.

The first image becomes available after this workflow lands on `master` and
completes. GitHub initially creates packages as private: a package administrator
must set `shadowsocks-c` to **Public** in its package settings before anonymous
pulls work. This is a one-time registry setting; see
[GitHub's container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#pushing-container-images).
Until then, the quick start also provides a local image build command.

## Build locally

The Alpine/musl builder uses Clang with LLD by default and links both third-party dependencies and libc statically.
`WITH_STATIC=ON` alone only selects static third-party libraries; this image also
passes `-DCMAKE_EXE_LINKER_FLAGS=-static` and omits shared-library outputs.
The compile, unit/vendor tests and six-method TCP/UDP relay tests run with Docker
network access disabled. The final ELF check rejects interpreters and dynamic
library dependencies. Initial image/toolchain installation requires networking.

From the repository root, export binaries and licenses (ARM64 example):

```sh
docker build --platform linux/arm64 -f docker/static/Dockerfile \
  --target artifacts --output type=local,dest=build-artifacts/static-linux-arm64 .
```

Requires Docker Buildx/BuildKit. If Docker Hub is unavailable, add
`--build-arg ALPINE_IMAGE=public.ecr.aws/docker/library/alpine:3.24`.
An alternate package mirror can be selected with `--build-arg ALPINE_MIRROR=https://mirrors.aliyun.com/alpine`; APK signature checks remain enabled.
Docker build proxy settings apply to package installation; a broken configured
proxy can be bypassed for this command with empty `HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY` build arguments and their lowercase equivalents.

Use `--platform linux/amd64` and a different destination for x86-64. Docker needs
a matching native builder or CPU emulation to compile and run the tests for a
foreign architecture. Add `--build-arg SS_MINIMAL=ON` for the minimal profile.

Build the scratch runtime image using the same cached build stage:

```sh
docker build --platform linux/arm64 -f docker/static/Dockerfile \
  --target runtime -t shadowsocks-c:static-arm64 .
docker run --rm -p 8388:8388/tcp -p 8388:8388/udp \
  shadowsocks-c:static-arm64 \
  -s 0.0.0.0 -p 8388 -k example-password -m aes-256-gcm -u
```

The runtime image has no shell or external plugin executables. Supply any SIP003
plugin and its own runtime requirements separately. Configuration files can be
bind-mounted and passed with `-c`. Exported binaries run on Linux with the same
CPU architecture; they do not run directly on macOS or Windows.
