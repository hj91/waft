# syntax=docker/dockerfile:1.7
# Copyright 2026 Bufferstack.IO Analytics Technology LLP
# SPDX-License-Identifier: Apache-2.0
# Multi-stage build: static binaries for waft-server, waft and waftd on a minimal,
# non-root runtime image. The web app is embedded in the server binary.

FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
# go mod tidy writes go.sum when it is not committed yet.
RUN go mod tidy \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/waft-server . \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/waft ./cmd/waft \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/waftd ./cmd/waftd

FROM alpine:3.20
LABEL org.opencontainers.image.title="Waft" \
      org.opencontainers.image.description="Self-hosted, multi-user, end-to-end encrypted device bus" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Bufferstack.IO Analytics Technology LLP"
RUN apk add --no-cache ca-certificates tzdata wget \
 && addgroup -S -g 10001 waft && adduser -S -D -H -u 10001 -G waft waft \
 && mkdir -p /app/uploads && chown waft:waft /app/uploads
COPY --from=build /out/ /usr/local/bin/
# Licence notices travel with the binaries (required by Apache-2.0 section 4 and the BSD/MIT licences).
COPY LICENSE NOTICE THIRD_PARTY_LICENSES /usr/share/doc/waft/
USER 10001:10001
WORKDIR /app
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/waft-server"]
