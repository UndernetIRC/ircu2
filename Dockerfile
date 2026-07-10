# Multi-stage build for ircu2 test harness
# Stage 1: Build ircu from source
FROM debian:trixie-slim AS builder

ARG TLS_BACKEND=openssl

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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/ircu2
COPY . .

# Remove any host-compiled binaries (e.g., macOS Mach-O) so make rebuilds for Linux
RUN find . -name '*.o' -delete && rm -f ircd/ircd

RUN ./autogen.sh \
    && ./configure --prefix=/opt/ircu --with-maxcon=256 --enable-debug --with-tls=${TLS_BACKEND} \
    && make

# Stage 2: Runtime image
FROM debian:trixie-slim

ARG TLS_BACKEND=openssl

RUN apt-get update && apt-get install -y --no-install-recommends \
    perl \
    $(if [ "$TLS_BACKEND" = "openssl" ]; then echo libssl3t64; \
      elif [ "$TLS_BACKEND" = "gnutls" ]; then echo libgnutls30t64; \
      elif [ "$TLS_BACKEND" = "libtls" ]; then echo libtls28t64; fi) \
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

# Create empty motd file
RUN touch /opt/ircu/lib/ircd.motd && chown ircu:ircu /opt/ircu/lib/ircd.motd

USER ircu
WORKDIR /opt/ircu

ENTRYPOINT ["/opt/ircu/bin/ircd"]
CMD ["-f", "/opt/ircu/lib/ircd.conf", "-n"]
