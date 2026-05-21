# ========================== ArxSentinel — Dockerfile =====================================
#
#   Multi-stage build: golang:1.26-alpine → distroless/static-debian12:nonroot
#
#   Stage "builder": compiles a fully-static binary (CGO_ENABLED=0).
#   Stage "final":   copies only the binary and the bundled container config
#                    into a distroless image with no shell or package manager.
#
#   Run: docker build --build-arg VERSION=$(cat VERSION) -t arxsentinel:local .
#
# =========================================================================================

# ── Stage 1: build ────────────────────────────────────────────────────────────────────────
# --platform=$BUILDPLATFORM: builder runs natively on the build host regardless of TARGETARCH.
# Without this flag, docker buildx emulates arm64 via QEMU which is 10-20x slower.
# Cross-compilation is handled by GOOS/GOARCH env vars in the go build step.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

# Build args propagated from docker build / GoReleaser.
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/arxsentinel \
      ./cmd/arxsentinel

# ── Stage 2: final ────────────────────────────────────────────────────────────────────────
# distroless/static: no libc, no shell, no package manager.
# :nonroot tag sets USER 65532:65532 — matches the nonroot group in the image.
FROM gcr.io/distroless/static-debian12:nonroot

# Copy binary and container-specific defaults config.
COPY --from=builder /out/arxsentinel /arxsentinel
COPY deploy/container/docker/config.docker.yaml /etc/arxsentinel/config.yaml

# 9117 — Prometheus /metrics endpoint (metrics.listen_addr default).
EXPOSE 9117

# distroless:nonroot already sets USER 65532 in its base — explicit for documentation.
USER nonroot:nonroot

ENTRYPOINT ["/arxsentinel"]
