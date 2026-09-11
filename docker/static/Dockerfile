ARG ALPINE_IMAGE=alpine:3.24
FROM ${ALPINE_IMAGE} AS build
ARG ALPINE_MIRROR=https://dl-cdn.alpinelinux.org/alpine
RUN sed -i "s|https://dl-cdn.alpinelinux.org/alpine|${ALPINE_MIRROR}|g" /etc/apk/repositories \
 && apk add --no-cache clang lld make musl-dev compiler-rt cmake linux-headers python3 binutils file
ENV CC=clang
WORKDIR /src
COPY . .
ARG SS_MINIMAL=OFF
RUN --network=none cmake -S . -B /build \
      -DCMAKE_BUILD_TYPE=Release \
      -DSS_DEPENDENCY_MODE=bundled -DWITH_STATIC=ON \
      -DSS_BUILD_STATIC_LIBRARY=OFF -DSS_BUILD_SHARED_LIBRARY=OFF \
      -DSS_MINIMAL=${SS_MINIMAL} -DCMAKE_EXE_LINKER_FLAGS="-static -fuse-ld=lld --rtlib=compiler-rt" \
      -DCMAKE_INSTALL_PREFIX=/out \
 && cmake --build /build --parallel 4 \
 && ctest --test-dir /build -L 'unit|vendor' --output-on-failure --no-tests=error \
 && python3 tests/interop.py --self --bin /build/bin \
 && cmake --install /build --strip \
 && for binary in /out/bin/ss-*; do \
      file "$binary"; \
      ! readelf -l "$binary" | grep -q INTERP || exit 1; \
      ! readelf -d "$binary" | grep -q NEEDED || exit 1; \
    done

# Export binaries and their license files with --target artifacts --output.
FROM scratch AS artifacts
COPY --from=build /out/ /

# No libc, dynamic loader, package manager or shell in the runtime image.
FROM scratch AS runtime
COPY --from=build /out/ /usr/local/
ENTRYPOINT ["/usr/local/bin/ss-server"]
