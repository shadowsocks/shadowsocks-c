# Development image for building shadowsocks-c. The default bundled mode
# builds every dependency from third_party/dist, so only a toolchain is
# needed (Alpine's Mbed TLS 4 is not supported by system mode).
FROM alpine

RUN apk add --no-cache --virtual .build-deps \
    build-base cmake ninja python3 linux-headers
