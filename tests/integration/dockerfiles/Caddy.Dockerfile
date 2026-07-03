# Build Caddy with the transform-encoder plugin required by the "caddy" sentinel profile.
# xcaddy fetches the plugin at build time; the resulting binary is a drop-in replacement.

# Fully-qualified image refs (docker.io/library/caddy, not bare "caddy"):
# FreeBSD podman has no unqualified-search-registries configured by
# default, so a short name fails with "did not resolve to an alias"
# (Flow 091 triage-caddy-1.md; same class of bug as Flow 088 Decision
# F.4). Fully-qualified names resolve identically under Linux Docker.
FROM docker.io/library/caddy:builder AS builder
# GOROOT explicit (workaround, Flow 091 triage-caddy-1.md P2.7 iter 3):
# the image's `go` binary is built with -trimpath, so at runtime it
# self-locates GOROOT via os.Executable() -> readlink /proc/self/exe.
# Under FreeBSD's linprocfs (Linux /proc emulation inside the podman
# Linux-compat container), that readlink fails ("no such file or
# directory"), so `go` can't find its own GOROOT and xcaddy's `go mod
# init` step dies. Setting GOROOT explicitly skips the self-location
# path entirely. Harmless under native Linux Docker (GOROOT env just
# overrides an already-correct auto-detected value there).
ENV GOROOT=/usr/local/go
RUN xcaddy build --with github.com/caddyserver/transform-encoder

FROM docker.io/library/caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
