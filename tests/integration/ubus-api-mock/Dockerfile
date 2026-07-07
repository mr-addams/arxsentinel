# ========================== ArxSentinel — uhttpd-mod-ubus mock server ===========================
#
#   Mock OpenWrt uhttpd-mod-ubus JSON-RPC endpoint for integration tests.
#   Emulates the /ubus entry point used by the openwrt executor to call
#   session.login, uci.{add_list,del_list,commit,get} and rc.init via
#   the ubus 'call' wrapper.
#
#   Build: docker build -t ubus-api-mock -f Dockerfile ..
#   Run:   docker run -p 8080:8080 ubus-api-mock
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
