# rustscale container image.
#
# Multi-stage build: Rust compiler → minimal Alpine runtime.
#
# Usage:
#   docker build -t rustscale .
#   docker run -d --name rustscale \
#     -e TS_AUTHKEY=tskey-... \
#     -e TS_HOSTNAME=my-container \
#     -v rustscale-state:/var/lib/rustscale \
#     rustscale
#
# For TUN mode (kernel networking), add --privileged and --device /dev/net/tun:
#   docker run -d --name rustscale \
#     -e TS_AUTHKEY=tskey-... \
#     --privileged --device /dev/net/tun \
#     rustscale
#
# See container/entrypoint.sh for the full env var reference.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM rust:1.91-alpine@sha256:45c1c35cd364b8055e9e86f8ecd3e8c874b2dcb658d8a4f94b5d111aa0d651a2 AS builder

# Beta images can disable LTO to keep cross-platform build times practical.
ARG RUSTSCALE_LTO=true

RUN apk add --no-cache musl-dev

WORKDIR /build

# Copy only manifests first for layer caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY vendor/boringtun/ ./vendor/boringtun/
COPY include/ ./include/

# Build release binaries. --locked ensures reproducible builds.
RUN CARGO_PROFILE_RELEASE_LTO=$RUSTSCALE_LTO cargo build --release --locked -p rustscale-cli -p rustscale-rustscaled

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

ARG RUSTSCALE_VERSION=dev
ARG RUSTSCALE_REVISION=unknown
LABEL org.opencontainers.image.title="rustscale" \
      org.opencontainers.image.description="Rust implementation of Tailscale's client stack" \
      org.opencontainers.image.source="https://github.com/rajsinghtech/rustscale" \
      org.opencontainers.image.licenses="BSD-3-Clause" \
      org.opencontainers.image.version="$RUSTSCALE_VERSION" \
      org.opencontainers.image.revision="$RUSTSCALE_REVISION"

RUN apk add --no-cache ca-certificates iptables iptables-legacy iproute2 ip6tables iputils

# Link to legacy iptables (same as Tailscale's image — some hosts don't
# support nftables).
RUN rm /usr/sbin/iptables && ln -s /usr/sbin/iptables-legacy /usr/sbin/iptables
RUN rm /usr/sbin/ip6tables && ln -s /usr/sbin/ip6tables-legacy /usr/sbin/ip6tables

COPY --from=builder /build/target/release/rustscale  /usr/local/bin/rustscale
COPY --from=builder /build/target/release/rustscaled /usr/local/bin/rustscaled
COPY container/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY LICENSE /usr/share/licenses/rustscale/LICENSE
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && ln -s rustscale /usr/local/bin/tailscale \
    && ln -s rustscaled /usr/local/bin/tailscaled

# State directory (mount a volume here for persistence).
RUN mkdir -p /var/lib/rustscale
VOLUME ["/var/lib/rustscale"]

# Default to userspace networking (no TUN device needed).
ENV TS_USERSPACE=1
ENV TS_STATE_DIR=/var/lib/rustscale

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
