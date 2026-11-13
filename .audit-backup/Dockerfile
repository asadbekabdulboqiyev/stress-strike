# syntax=docker/dockerfile:1

###############################################################################
# Stage 1 — builder: compile all 6 binaries.
#   replay requires CGO + libpcap (gopacket/pcap); everything else is pure Go.
###############################################################################
FROM golang:1.26-alpine AS builder

ARG VERSION=0.11.0

# Build deps for CGO (replay binary needs libpcap for gopacket/pcap).
RUN apk add --no-cache build-base libpcap-dev

WORKDIR /src

# Cache dependency downloads in their own layer.
COPY go.mod go.sum ./
RUN go mod download

# Copy the full source tree.
COPY . .

# Build the 5 pure-Go binaries (no CGO needed).
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/Sift           ./cmd/Sift && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/Sift-dashboard ./cmd/Sift-dashboard && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/Sift-master    ./cmd/Sift-master && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/Sift-worker    ./cmd/Sift-worker && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/Sift-scan      ./cmd/Sift-scan

# Build replay with CGO (needs libpcap for gopacket/pcap).
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/Sift-replay ./cmd/Sift-replay

###############################################################################
# Stage 2 — runtime: minimal Alpine image with all binaries.
###############################################################################
FROM alpine:3.21

ARG VERSION=0.11.0

LABEL org.opencontainers.image.title="Sift" \
      org.opencontainers.image.description="Distributed load testing & network simulator written in Go" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.vendor="Sift"

# CA certs for HTTPS targets; libpcap for replay at runtime; non-root user.
RUN apk add --no-cache ca-certificates libpcap \
    && adduser -D -H -u 10001 stress

WORKDIR /app

RUN mkdir -p /app/reports && chown stress:stress /app/reports

# Copy all 6 binaries into the runtime image.
COPY --from=builder /out/Sift           /usr/local/bin/Sift
COPY --from=builder /out/Sift-dashboard /usr/local/bin/Sift-dashboard
COPY --from=builder /out/Sift-master    /usr/local/bin/Sift-master
COPY --from=builder /out/Sift-worker    /usr/local/bin/Sift-worker
COPY --from=builder /out/Sift-replay    /usr/local/bin/Sift-replay
COPY --from=builder /out/Sift-scan      /usr/local/bin/Sift-scan

USER stress

# Ports: 8888 = dashboard UI, 50051 = master gRPC, 50052 = worker gRPC
EXPOSE 8888 50051 50052

VOLUME ["/app/reports"]

ENTRYPOINT ["Sift"]
