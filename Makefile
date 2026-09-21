GO ?= go
BUILD_IMAGE ?= blackbox-tools
IMAGE ?= blackbox
GO_MOD_VOLUME ?= blackbox-go-mod
GO_BUILD_VOLUME ?= blackbox-go-build
TOOL_MOUNTS = -v '$(CURDIR):/build' -v $(GO_MOD_VOLUME):/go/pkg/mod -v $(GO_BUILD_VOLUME):/root/.cache/go-build
COMPOSE = docker compose
LDFLAGS = -s -w

.DEFAULT_GOAL := help
.PHONY: help build build-linux dist test vet check docs docs-check licenses licenses-check bench fuzz demo toolchain generate integration docker up down status clean
help:
	@echo 'build / build-linux  Static native / Linux amd64+arm64 binaries'
	@echo 'dist                  Versioned Linux release archives and checksums'
	@echo 'check                Race tests, vet, Linux builds, generated docs check'
	@echo 'docs                 Regenerate CLI reference, example config and Docker Go version'
	@echo 'licenses             Regenerate third-party license and notice files'
	@echo 'generate             Regenerate Go/ELF sensor files and histogram ABI'
	@echo 'integration          Privileged tests on the local Linux kernel / Docker VM'
	@echo 'bench / fuzz         Recorder benchmarks / bounded capture decoder fuzzing'
	@echo 'docker / up          Build runtime image / build and start local Compose'
	@echo 'status / down        Inspect / stop local Compose (down does not remove volumes)'

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/blackbox ./cmd/blackbox
build-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/blackbox-linux-amd64 ./cmd/blackbox
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/blackbox-linux-arm64 ./cmd/blackbox
dist:
	GO='$(GO)' ./scripts/release.sh
test:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
check: test vet build-linux docs-check licenses-check
docs:
	$(GO) run ./internal/tools/docgen
docs-check:
	$(GO) run ./internal/tools/docgen -check
licenses:
	GO='$(GO)' ./scripts/licenses.sh generate
licenses-check:
	GO='$(GO)' ./scripts/licenses.sh check
bench:
	$(GO) test ./internal/recorder -run '^$$' -bench . -benchmem
fuzz:
	$(GO) test ./internal/capture -run '^$$' -fuzz FuzzContainerRead -fuzztime 10s -parallel 2
demo: build
	./bin/blackbox demo -o demo.bbx
	./bin/blackbox analyze demo.bbx
toolchain:
	docker build -f Dockerfile.tools -t $(BUILD_IMAGE) .
generate: toolchain
	docker run --rm $(TOOL_MOUNTS) $(BUILD_IMAGE) go generate ./internal/sensor
integration: toolchain
	docker run --rm --privileged --pid=host $(TOOL_MOUNTS) $(BUILD_IMAGE) go test -tags integration -v ./test/integration ./internal/sensor
docker:
	docker build --target runtime -t $(IMAGE) .
up:
	@test -f config.yml || cp config.example.yml config.yml
	mkdir -p captures
	$(COMPOSE) up -d --build
status:
	$(COMPOSE) exec blackbox /app/blackbox status
down:
	$(COMPOSE) down
clean:
	rm -rf bin coverage dist
