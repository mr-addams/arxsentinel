# ========================== ArxSentinel — ROS API mock server ===========================
#
#   Mock MikroTik RouterOS API server for integration tests. Simulates REST API
#   responses (firewall rules, address lists) returned by the real RouterOS.
#
#   Build: docker build -t ros-api-mock -f Dockerfile ..
#   Run:   docker run -p 8080:8080 ros-api-mock
#
# =========================================================================================

# ── Stage 1: build ────────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY server.go .
RUN go mod init ros-api-mock && go build -o server .

# ── Stage 2: final ───────────────────────────────────────────────────────────────────
FROM alpine:latest

COPY --from=builder /app/server /server

EXPOSE 8080

ENTRYPOINT ["/server"]