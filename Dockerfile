# Multi-stage build for ircu2 test harness
# Stage 1: Build ircu from source
FROM debian:trixie-slim AS builder

ARG TLS_BACKEND=openssl
ARG SANITIZE=

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    bison \
    flex \
    autoconf \
    automake \
    autoconf-archive \
    libc6-dev \
    pkg-config \
    $(if [ "$TLS_BACKEND" = "openssl" ]; then echo libssl-dev; \
      elif [ "$TLS_BACKEND" = "gnutls" ]; then echo libgnutls28-dev; \
      elif [ "$TLS_BACKEND" = "libtls" ]; then echo libtls-dev; fi) \
    $(if [ -n "$SANITIZE" ]; then echo libasan8; fi) \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/ircu2
COPY . .

# Remove any host-compiled binaries (e.g., macOS Mach-O) so make rebuilds for Linux
RUN find . -name '*.o' -delete && rm -f ircd/ircd

RUN ./autogen.sh \
    && if [ -n "$SANITIZE" ]; then \
         export CFLAGS="-fsanitize=$SANITIZE -fno-omit-frame-pointer -g -O1"; \
         export LDFLAGS="-fsanitize=$SANITIZE"; \
       fi; \
    ./configure --prefix=/opt/ircu --with-maxcon=256 --enable-debug --with-tls=${TLS_BACKEND} \
    && make

# Stage 2: Runtime image
FROM debian:trixie-slim

ARG TLS_BACKEND=openssl
ARG SANITIZE=

RUN apt-get update && apt-get install -y --no-install-recommends \
    perl \
    gdb \
    valgrind \
    $(if [ "$TLS_BACKEND" = "openssl" ]; then echo libssl3t64; \
      elif [ "$TLS_BACKEND" = "gnutls" ]; then echo libgnutls30t64; \
      elif [ "$TLS_BACKEND" = "libtls" ]; then echo libtls28t64; fi) \
    $(if [ -n "$SANITIZE" ]; then echo libasan8; fi) \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -m -d /opt/ircu ircu

COPY --from=builder /build/ircu2/ircd/ircd /opt/ircu/bin/ircd
RUN mkdir -p /opt/ircu/lib /opt/ircu/bin && chown -R ircu:ircu /opt/ircu

# Copy config file into image (passed as build arg)
ARG IRCD_CONF=tests/docker/ircd-hub.conf
COPY ${IRCD_CONF} /opt/ircu/lib/ircd.conf
RUN chown ircu:ircu /opt/ircu/lib/ircd.conf

# TLS test certificates (no-op for non-TLS configs)
COPY tests/docker/certs /opt/ircu/lib/certs
RUN chown -R ircu:ircu /opt/ircu/lib/certs

# IAuth stub used by the DNS resolver tests (harmless for other configs)
COPY tests/docker/iauth-dns-stub.pl /opt/ircu/lib/iauth-dns-stub.pl
RUN chown ircu:ircu /opt/ircu/lib/iauth-dns-stub.pl

# Create empty motd file
RUN touch /opt/ircu/lib/ircd.motd && chown ircu:ircu /opt/ircu/lib/ircd.motd

COPY tests/docker/iauth-tilded.pl /opt/ircu/bin/iauth-tilded.pl
RUN chmod +x /opt/ircu/bin/iauth-tilded.pl && chown ircu:ircu /opt/ircu/bin/iauth-tilded.pl

COPY tests/docker/ircd-entrypoint.sh /opt/ircu/lib/ircd-entrypoint.sh
RUN chmod 755 /opt/ircu/lib/ircd-entrypoint.sh

WORKDIR /opt/ircu

ENTRYPOINT ["/opt/ircu/lib/ircd-entrypoint.sh"]
CMD ["-f", "/opt/ircu/lib/ircd.conf", "-n"]
