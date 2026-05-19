# Build Caddy with the transform-encoder plugin required by the "caddy" sentinel profile.
# xcaddy fetches the plugin at build time; the resulting binary is a drop-in replacement.

FROM caddy:builder AS builder
RUN xcaddy build --with github.com/caddyserver/transform-encoder

FROM caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
