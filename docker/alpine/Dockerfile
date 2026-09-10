FROM alpine:3.16
LABEL maintainer="kev <noreply@datageek.info>, Sah <contact@leesah.name>, vndroid <waveworkshop@outlook.com>"

ENV SERVER_ADDR=0.0.0.0
ENV SERVER_PORT=8388
ENV PASSWORD=
ENV METHOD=aes-256-gcm
ENV TIMEOUT=300
ENV DNS_ADDRS="8.8.8.8,8.8.4.4"
ENV TZ=UTC
ENV ARGS=

COPY . /tmp/repo
RUN set -x \
 # Build environment setup
 && apk add --no-cache --virtual .build-deps \
      build-base \
      cmake \
      libcap \
      linux-headers \
 # Build & install
 && cd /tmp/repo \
 && mkdir -p build && cd build \
 && cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_TESTING=OFF -DSS_BUILD_STATIC_LIBRARY=OFF -DSS_BUILD_SHARED_LIBRARY=OFF -DCMAKE_BUILD_TYPE=Release \
 && make -j$(getconf _NPROCESSORS_ONLN) \
 && make install \
 && cd /usr/local/bin \
 && ls /usr/local/bin/ss-* | xargs -n1 setcap cap_net_bind_service+ep \
 && strip $(ls /usr/local/bin | grep -Ev 'ss-nat') \
 && apk del .build-deps \
 # Runtime dependencies setup
 && apk add --no-cache \
      ca-certificates \
      rng-tools \
      tzdata \
      $(scanelf --needed --nobanner /usr/local/bin/ss-* \
      | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
      | sort -u) \
 && rm -rf /tmp/repo

COPY ./docker/alpine/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 8388

STOPSIGNAL SIGINT

CMD ["ss-server"]
