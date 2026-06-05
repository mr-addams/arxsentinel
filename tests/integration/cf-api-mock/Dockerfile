# ========================== ArxSentinel — CF API mock server =============================
#
#   Mock Cloudflare API server for integration tests. Simulates WAF responses,
#   rate limiting, and various HTTP status codes returned by the real CF API.
#
#   Build: docker build -t cf-api-mock -f Dockerfile ..
#   Run:   docker run -p 9001:9001 cf-api-mock
#
# =========================================================================================

# ── Stage 1: build ────────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY server.go .
RUN go mod init cf-api-mock && go build -o server .

# ── Stage 2: final ───────────────────────────────────────────────────────────────────
FROM alpine:latest

COPY --from=builder /app/server /server

EXPOSE 9001

ENTRYPOINT ["/server"]