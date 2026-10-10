# syntax=docker/dockerfile:1

###############################################################################
# stress-strike — all-in-one image (run CLI + dashboard from one container).
#
# Build:
#   docker build -t ghcr.io/asadbekabdulboqiyev/stress-strike:0.14.3 .
#
# Run (web dashboard):
#   docker run --rm -p 8888:8888 ghcr.io/asadbekabdulboqiyev/stress-strike:0.14.3 \
#     run --url https://example.com --users 100 --duration 60 \
#          --mode dashboard --listen :8888
#
# AGPL-3.0: LICENSE is copied into the image (§4 requires the license text to
# travel with the binary). The previous image shipped no license file.
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
RUN set -eux; \
    for pkg in ./cmd/...; do \
        name="$(basename "$pkg")"; \
        CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" \
        go build -trimpath \
          -ldflags="-s -w \
            -X main.version=${VERSION} \
            -X github.com/asadbekabdulboqiyev/stress-strike/internal/version.Version=${VERSION} \
            -X github.com/asadbekabdulboqiyev/stress-strike/internal/version.Commit=${REVISION}" \
          -o "/out/${name}" "$pkg"; \
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
      org.opencontainers.image.licenses="AGPL-3.0" \
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

# AGPL-3.0 §4.
COPY LICENSE /usr/share/doc/stress-strike/LICENSE

USER 10001:10001

EXPOSE 8888 50051 50052

VOLUME ["/app/reports"]

# The Go code installs a SIGTERM handler in every long-running mode
# (signal.Notify on SIGINT/SIGTERM), so Docker's default stop signal is
# already the graceful one. Stated explicitly so it is not "fixed" later.
STOPSIGNAL SIGTERM

# No shell-based probe is possible once the CMD is the load binary, and the
# dashboard port only opens in `--mode dashboard`. Leaving HEALTHCHECK to the
# compose deploy (which knows the mode) is deliberate: a probe here would mark
# healthy CLI invocations as failing and restart them.
#
# docker-compose.yml carries the matching probe:
#   healthcheck:
#     test: ["CMD", "stress-strike", "dashboard-health", "--listen", "127.0.0.1:8888"]

ENTRYPOINT ["stress-strike"]
