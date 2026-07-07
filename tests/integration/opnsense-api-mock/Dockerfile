# ========================== ArxSentinel — OPNsense REST API mock server ==========================
#
#   Mock OPNsense firewall REST API for integration tests.
#   Emulates the /api/firewall/alias_util/{add,delete,list} endpoints
#   used by the opnsense executor to ban/unban IPs on a pre-existing
#   alias of type Host / Network / External. HTTP Basic Auth is
#   enforced (ENV-driven credentials).
#
#   Build: docker build -t opnsense-api-mock -f Dockerfile ..
#   Run:   docker run -p 8080:8080 \
#            -e OPNSENSE_MOCK_API_KEY=testkey \
#            -e OPNSENSE_MOCK_API_SECRET=testsecret \
#            opnsense-api-mock
#
# =================================================================================================

# ── Stage 1: build ──────────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY server.go .
COPY go.mod .
RUN go build -o server .

# ── Stage 2: final ─────────────────────────────────────────────────────────────────────
FROM alpine:latest

COPY --from=builder /app/server /server

EXPOSE 8080

ENTRYPOINT ["/server"]
