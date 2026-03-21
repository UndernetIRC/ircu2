# Multi-stage build for ircu2 test harness
# Stage 1: Build ircu from source
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    bison \
    flex \
    autoconf \
    automake \
    libc6-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/ircu2
COPY . .

# Remove any host-compiled binaries (e.g., macOS Mach-O) so make rebuilds for Linux
RUN find . -name '*.o' -delete && rm -f ircd/ircd

# Touch generated files to prevent make from trying to regenerate them
# (the container may have a different autoconf version than what generated these)
RUN touch aclocal.m4 configure config.h.in stamp-h.in

RUN ./configure --prefix=/opt/ircu --with-maxcon=256 --enable-debug \
    && make

# Stage 2: Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    perl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -m -d /opt/ircu ircu

COPY --from=builder /build/ircu2/ircd/ircd /opt/ircu/bin/ircd
RUN mkdir -p /opt/ircu/lib /opt/ircu/bin && chown -R ircu:ircu /opt/ircu

# Copy config file into image (passed as build arg)
ARG IRCD_CONF=tests/docker/ircd-hub.conf
COPY ${IRCD_CONF} /opt/ircu/lib/ircd.conf
RUN chown ircu:ircu /opt/ircu/lib/ircd.conf

# Create empty motd file
RUN touch /opt/ircu/lib/ircd.motd && chown ircu:ircu /opt/ircu/lib/ircd.motd

USER ircu
WORKDIR /opt/ircu

ENTRYPOINT ["/opt/ircu/bin/ircd"]
CMD ["-f", "/opt/ircu/lib/ircd.conf", "-n"]
