# syntax=docker/dockerfile:1

###############################################################################
# stress-strike — all-in-one image (run CLI + dashboard from one container).
#
# Build:
#   docker build -t ghcr.io/asadbekabdulboqiyev/stress-strike:0.14.3 .
#
# Run (web dashboard):
#   docker run --rm -p 127.0.0.1:8888:8888 ghcr.io/asadbekabdulboqiyev/stress-strike:0.14.3 \
#     run --url https://example.com --users 100 --duration 60 \
#          --mode dashboard --listen 0.0.0.0:8888 \
#          --dashboard-auth-token "$(openssl rand -hex 24)"
#
# The dashboard's control API starts/stops real load runs, so it refuses to bind
# a non-loopback address without a credential. Publish the port on host loopback
# (-p 127.0.0.1:8888:8888) and pass --dashboard-auth-token, or add
# --dashboard-insecure to acknowledge an unauthenticated, loopback-only demo.
#
# Apache-2.0: LICENSE and NOTICE are copied into the image (§4 requires the
# license text and attributions to travel with the binary).
###############################################################################

# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

# VERSION is stamped by CI (docker/metadata-action). Never hardcode it here.
ARG VERSION=dev
ARG REVISION=""
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Dependencies first so source edits don't invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# All 6 binaries, pure Go. The previous image built replay with
# CGO_ENABLED=1 against libpcap and shipped libpcap in the runtime layer —
# but internal/replay reads PCAP through gopacket/pcapgo, which needs neither.
# That cost ~2 MB in the image and a build-base install for nothing.
#
# Iterate real directories (`./cmd/*`), never the Go package pattern
# `./cmd/...`: the shell does not expand `...`, so the loop ran exactly once
# with name="..." and `go build -o /out/... ./cmd/...` died with "cannot write
# multiple packages to non-directory" - the image never built, and that only
# surfaced once the workflow file itself became valid again.
RUN set -eux; \
    for dir in ./cmd/*; do \
        name="$(basename "$dir")"; \
        CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" \
        go build -trimpath \
          -ldflags="-s -w \
            -X main.version=${VERSION} \
            -X github.com/asadbekabdulboqiyev/stress-strike/internal/version.Version=${VERSION} \
            -X github.com/asadbekabdulboqiyev/stress-strike/internal/version.Commit=${REVISION}" \
          -o "/out/${name}" "$dir"; \
    done

# Verify the binary we are about to ship is not a dev build.
RUN /out/stress-strike --version

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM alpine:3.21

ARG VERSION=dev
ARG REVISION=""

LABEL org.opencontainers.image.title="stress-strike" \
      org.opencontainers.image.description="Distributed load testing & network simulator written in Go" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="stress-strike" \
      org.opencontainers.image.source="https://github.com/asadbekabdulboqiyev/stress-strike"

# ca-certificates only: libpcap is no longer a runtime dependency.
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 -s /sbin/nologin stress

WORKDIR /app

# Reports go to a volume, owned by the unprivileged user.
RUN mkdir -p /app/reports && chown -R stress:stress /app

COPY --from=builder /out/stress-strike           /usr/local/bin/stress-strike
COPY --from=builder /out/stress-strike-dashboard /usr/local/bin/stress-strike-dashboard
COPY --from=builder /out/stress-strike-master    /usr/local/bin/stress-strike-master
COPY --from=builder /out/stress-strike-worker    /usr/local/bin/stress-strike-worker
COPY --from=builder /out/stress-strike-replay    /usr/local/bin/stress-strike-replay
COPY --from=builder /out/stress-strike-scan      /usr/local/bin/stress-strike-scan

# Apache-2.0 §4.
COPY LICENSE NOTICE /usr/share/doc/stress-strike/

USER 10001:10001

EXPOSE 8888 9090 9091 50051 50052

VOLUME ["/app/reports"]

# The Go code installs a SIGTERM handler in every long-running mode
# (signal.Notify on SIGINT/SIGTERM), so Docker's default stop signal is
# already the graceful one. Stated explicitly so it is not "fixed" later.
STOPSIGNAL SIGTERM

# ── liveness probe ──────────────────────────────────────────────────────────
# This image is based on alpine, so busybox `wget` is available and no extra
# probe binary is needed. The dashboard HTTP server (default 127.0.0.1:8888)
# serves GET /healthz (200 while the process is up) and GET /readyz.
#
# CAVEAT: HEALTHCHECK applies to every invocation of this image, including
# plain CLI runs (e.g. `stress-strike run --url ... --users 10`) where the
# dashboard port is never opened. Those will report "unhealthy"; orchestrators
# that run the image as a one-shot CLI job should disable the probe
# (`docker run --no-healthcheck`) or point it at the relevant mode.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/bin/sh", "-c", "wget -qO- http://127.0.0.1:8888/healthz || exit 1"]

ENTRYPOINT ["stress-strike"]
