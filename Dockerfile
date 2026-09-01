# syntax=docker/dockerfile:1

###############################################################################
# Stage 1 — builder: compile all 6 binaries.
#   replay requires CGO + libpcap (gopacket/pcap); everything else is pure Go.
###############################################################################
FROM golang:1.26-alpine AS builder

ARG VERSION=0.9.0

# Build deps for CGO (replay binary needs libpcap for gopacket/pcap).
RUN apk add --no-cache build-base libpcap-dev

WORKDIR /src

# Cache dependency downloads in their own layer.
COPY go.mod go.sum ./
RUN go mod download

# Copy the full source tree.
COPY . .

# Build the 5 pure-Go binaries (no CGO needed).
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/stress-strike           ./cmd/stress-strike && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/stress-strike-dashboard ./cmd/stress-strike-dashboard && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/stress-strike-master    ./cmd/stress-strike-master && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/stress-strike-worker    ./cmd/stress-strike-worker && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/stress-strike-scan      ./cmd/stress-strike-scan

# Build replay with CGO (needs libpcap for gopacket/pcap).
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/stress-strike-replay ./cmd/stress-strike-replay

###############################################################################
# Stage 2 — runtime: minimal Alpine image with all binaries.
###############################################################################
FROM alpine:latest

ARG VERSION=0.9.0

LABEL org.opencontainers.image.title="stress-strike" \
      org.opencontainers.image.description="Distributed load testing & network simulator written in Go" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.vendor="stress-strike"

# CA certs for HTTPS targets; libpcap for replay at runtime; non-root user.
RUN apk add --no-cache ca-certificates libpcap \
    && adduser -D -H -u 10001 stress

WORKDIR /app

RUN mkdir -p /app/reports && chown stress:stress /app/reports

# Copy all 6 binaries into the runtime image.
COPY --from=builder /out/stress-strike           /usr/local/bin/stress-strike
COPY --from=builder /out/stress-strike-dashboard /usr/local/bin/stress-strike-dashboard
COPY --from=builder /out/stress-strike-master    /usr/local/bin/stress-strike-master
COPY --from=builder /out/stress-strike-worker    /usr/local/bin/stress-strike-worker
COPY --from=builder /out/stress-strike-replay    /usr/local/bin/stress-strike-replay
COPY --from=builder /out/stress-strike-scan      /usr/local/bin/stress-strike-scan

USER stress

# Ports: 8888 = dashboard UI, 50051 = master gRPC, 50052 = worker gRPC
EXPOSE 8888 50051 50052

VOLUME ["/app/reports"]

ENTRYPOINT ["stress-strike"]
