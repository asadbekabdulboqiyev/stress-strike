# syntax=docker/dockerfile:1

###############################################################################
# Stage 1 — builder: compile a static, stripped stress-strike binary.
###############################################################################
FROM golang:1.26-alpine AS builder

# Build-arg version (injected by `make release` flow or docker build --build-arg).
# Kept as an image label; stress-strike's version const lives in cmd source.
ARG VERSION=0.2.0

WORKDIR /src

# Cache dependency downloads in their own layer (rebuild only when deps change).
COPY go.mod go.sum ./
RUN go mod download

# Copy the full source and build a static (CGO_ENABLED=0) binary.
COPY . .
RUN CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/stress-strike ./cmd/stress-strike

###############################################################################
# Stage 2 — runtime: minimal Alpine image, non-root, /app as working dir.
###############################################################################
FROM alpine:latest

ARG VERSION=0.2.0

LABEL org.opencontainers.image.title="stress-strike" \
      org.opencontainers.image.description="Load testing & network simulator written in Go" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

# CA certs so HTTPS targets work out of the box; dedicated non-root user.
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 stress

WORKDIR /app

# Reports are written into ./reports by default; expose a data volume there.
RUN mkdir -p /app/reports && chown stress:stress /app/reports

COPY --from=builder /out/stress-strike /usr/local/bin/stress-strike

USER stress

# A load generator serves no HTTP itself; it runs its tests then exits.
# Override flags at runtime: docker run stress-strike --url ... --users ...
ENTRYPOINT ["stress-strike"]