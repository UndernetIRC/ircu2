# Multi-stage build for ircu2 test harness
#
# Targets:
#   runtime-tree     — build from the working tree (default; last stage)
#   runtime-release  — download and build a tagged UndernetIRC/ircu2 release
#                      (used as the "prod" peer in NETWORK_FEATURES compat tests)

ARG TLS_BACKEND=openssl
ARG SANITIZE=
ARG IRCD_RELEASE_TAG=u2.10.12.19

# ---------------------------------------------------------------------------
# Stage: build from the current working tree
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS builder-tree

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

# ---------------------------------------------------------------------------
# Stage: build the current Undernet production release from GitHub
# https://github.com/UndernetIRC/ircu2/releases
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS builder-release

ARG IRCD_RELEASE_TAG=u2.10.12.19

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    bison \
    flex \
    libc6-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl -fsSL \
      "https://github.com/UndernetIRC/ircu2/archive/refs/tags/${IRCD_RELEASE_TAG}.tar.gz" \
      -o /tmp/ircu-release.tar.gz \
    && tar xzf /tmp/ircu-release.tar.gz \
    && rm /tmp/ircu-release.tar.gz \
    && SRC="$(echo ircu2-*)" \
    && cd "$SRC" \
    && ./configure --prefix=/opt/ircu --with-maxcon=256 --enable-debug \
    && make \
    && cp ircd/ircd /build/ircd

# ---------------------------------------------------------------------------
# Shared runtime base (no ircd binary yet)
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime-base

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

RUN useradd -r -m -d /opt/ircu ircu \
    && mkdir -p /opt/ircu/lib /opt/ircu/bin \
    && chown -R ircu:ircu /opt/ircu

ARG IRCD_CONF=tests/docker/ircd-hub.conf
COPY ${IRCD_CONF} /opt/ircu/lib/ircd.conf
RUN chown ircu:ircu /opt/ircu/lib/ircd.conf

COPY tests/docker/certs /opt/ircu/lib/certs
RUN chown -R ircu:ircu /opt/ircu/lib/certs

# IAuth stub used by the DNS resolver tests (harmless for other configs)
COPY tests/docker/iauth-dns-stub.pl /opt/ircu/lib/iauth-dns-stub.pl
RUN chown ircu:ircu /opt/ircu/lib/iauth-dns-stub.pl

# Create empty motd file
RUN touch /opt/ircu/lib/ircd.motd && chown ircu:ircu /opt/ircu/lib/ircd.motd

COPY tests/docker/ircd-entrypoint.sh /opt/ircu/lib/ircd-entrypoint.sh
RUN chmod 755 /opt/ircu/lib/ircd-entrypoint.sh

WORKDIR /opt/ircu

ENTRYPOINT ["/opt/ircu/lib/ircd-entrypoint.sh"]
CMD ["-f", "/opt/ircu/lib/ircd.conf", "-n"]

# ---------------------------------------------------------------------------
# Final: production release binary (NETWORK_FEATURES compat peer "A")
# ---------------------------------------------------------------------------
FROM runtime-base AS runtime-release
COPY --from=builder-release /build/ircd /opt/ircu/bin/ircd
RUN chown ircu:ircu /opt/ircu/bin/ircd

# ---------------------------------------------------------------------------
# Final: working-tree binary (default target — must stay last)
# ---------------------------------------------------------------------------
FROM runtime-base AS runtime-tree
COPY --from=builder-tree /build/ircu2/ircd/ircd /opt/ircu/bin/ircd
RUN chown ircu:ircu /opt/ircu/bin/ircd
