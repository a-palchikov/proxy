# syntax=docker/dockerfile:1.6

ARG GO_DOCKER_BASE
ARG DOCKER_BASE
FROM ${GO_DOCKER_BASE} AS builder
WORKDIR /src
ARG BUILDKIT_SBOM_SCAN_STAGE=true
COPY . . 
RUN \
  --mount=type=cache,target=/root/.cache --mount=type=cache,target=/go/pkg/mod <<eof
  make build CGO_ENABLED=0
eof

ARG GO_DOCKER_BASE
FROM ${DOCKER_BASE} AS releaser
LABEL org.opencontainers.image.source="https://github.com/a-palchikov/proxy"

COPY --from=builder /src/_build/proxy /

CMD ["/proxy"]
