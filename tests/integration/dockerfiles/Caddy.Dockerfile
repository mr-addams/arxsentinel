# Build Caddy with the transform-encoder plugin required by the "caddy" sentinel profile.
# xcaddy fetches the plugin at build time; the resulting binary is a drop-in replacement.

# Fully-qualified image refs (docker.io/library/caddy, not bare "caddy"):
# FreeBSD podman has no unqualified-search-registries configured by
# default, so a short name fails with "did not resolve to an alias"
# (Flow 091 triage-caddy-1.md; same class of bug as Flow 088 Decision
# F.4). Fully-qualified names resolve identically under Linux Docker.
FROM docker.io/library/caddy:builder AS builder
RUN xcaddy build --with github.com/caddyserver/transform-encoder

FROM docker.io/library/caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
