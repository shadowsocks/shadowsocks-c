# Fully static Linux builds

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
