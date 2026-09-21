# syntax=docker/dockerfile:1
# Synchronized from go.mod by make docs.
ARG GO_VERSION=1.27.1
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /build/blackbox ./cmd/blackbox

# Runtime: static binary and license texts; no compiler or default command.
FROM scratch AS runtime
WORKDIR /app
# Recording needs root. Offline analysis can use --user.
USER 0:0
COPY --from=build /build/blackbox /app/blackbox
COPY --from=build /build/LICENSE /usr/share/licenses/blackbox/LICENSE
COPY --from=build /build/LICENSES/GPL-2.0-only.txt /usr/share/licenses/blackbox/GPL-2.0-only.txt
COPY --from=build /build/third_party/licenses /usr/share/licenses/blackbox/third-party
ENTRYPOINT ["/app/blackbox"]
