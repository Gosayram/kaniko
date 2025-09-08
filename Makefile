# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Single source of truth for version from .release-version file
VERSION ?= $(shell cat .release-version 2>/dev/null || echo v1.24.0)
# Extract version components for backward compatibility
VERSION_MAJOR ?= $(shell echo $(VERSION) | sed 's/^v//' | cut -d. -f1)
VERSION_MINOR ?= $(shell echo $(VERSION) | sed 's/^v//' | cut -d. -f2)
VERSION_BUILD ?= $(shell echo $(VERSION) | sed 's/^v//' | cut -d. -f3)

VERSION_PACKAGE = $(REPOPATH)/internal/version

SHELL := /bin/bash
GOOS ?= linux
GOARCH ?= amd64
ORG := github.com/Gosayram
PROJECT := kaniko
GOPATH ?= $(shell go env GOPATH)
GOLANGCI_LINT = $(GOPATH)/bin/golangci-lint
REGISTRY?=gcr.io/Gosayram/kaniko

REPOPATH ?= $(ORG)/$(PROJECT)

GO_FILES := $(shell find . -type f -name '*.go' -not -path "./vendor/*")
GO_LDFLAGS := '-extldflags "-static"
GO_LDFLAGS += -X $(VERSION_PACKAGE).Version=$(VERSION)
GO_LDFLAGS += -X $(VERSION_PACKAGE).Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
GO_LDFLAGS += -X $(VERSION_PACKAGE).Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_LDFLAGS += -w -s # Drop debugging symbols.
GO_LDFLAGS += '

EXECUTOR_PACKAGE = $(REPOPATH)/cmd/executor
WARMER_PACKAGE = $(REPOPATH)/cmd/warmer
KANIKO_PROJECT = $(REPOPATH)/kaniko
BUILD_ARG ?=

# Force using Go Modules and always read the dependencies from
# the `vendor` folder.
export GO111MODULE = on
export GOFLAGS = -mod=vendor

clean:
	@echo "Cleaning up..."
	rm -rf out/
	@echo "Done."

out/executor: $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=$(GOOS) CGO_ENABLED=0 go build -ldflags $(GO_LDFLAGS) -o $@ $(EXECUTOR_PACKAGE)

out/warmer: $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=$(GOOS) CGO_ENABLED=0 go build -ldflags $(GO_LDFLAGS) -o $@ $(WARMER_PACKAGE)

.PHONY: install-container-diff
install-container-diff:
	@ curl -LO https://github.com/Gosayram/container-diff/releases/download/v0.17.0/container-diff-$(GOOS)-amd64 && \
		chmod +x container-diff-$(GOOS)-amd64 && sudo mv container-diff-$(GOOS)-amd64 /usr/local/bin/container-diff

.PHONY: k3s-setup
k3s-setup:
	@ ./scripts/k3s-setup.sh

.PHONY: test
test: out/executor
	@ ./scripts/test.sh

test-with-coverage: test
	go tool cover -html=out/coverage.out


.PHONY: integration-test
integration-test:
	@ ./scripts/integration-test.sh

.PHONY: integration-test-run
integration-test-run:
	@ ./scripts/integration-test.sh -run "TestRun"

.PHONY: integration-test-layers
integration-test-layers:
	@ ./scripts/integration-test.sh -run "TestLayers"

.PHONY: integration-test-k8s
integration-test-k8s:
	@ ./scripts/integration-test.sh -run "TestK8s"

.PHONY: integration-test-misc
integration-test-misc:
	$(eval RUN_ARG=$(shell ./scripts/misc-integration-test.sh))
	@ ./scripts/integration-test.sh -run "$(RUN_ARG)"

.PHONY: images
images: DOCKER_BUILDKIT=1
images:
	@echo "Building Docker images..."
	docker build ${BUILD_ARG} --build-arg=TARGETARCH=$(GOARCH) --build-arg=TARGETOS=linux -t $(REGISTRY)/executor:latest -f deploy/Dockerfile --target kaniko-executor .
	docker build ${BUILD_ARG} --build-arg=TARGETARCH=$(GOARCH) --build-arg=TARGETOS=linux -t $(REGISTRY)/executor:debug -f deploy/Dockerfile --target kaniko-debug .
	docker build ${BUILD_ARG} --build-arg=TARGETARCH=$(GOARCH) --build-arg=TARGETOS=linux -t $(REGISTRY)/executor:slim -f deploy/Dockerfile --target kaniko-slim .
	docker build ${BUILD_ARG} --build-arg=TARGETARCH=$(GOARCH) --build-arg=TARGETOS=linux -t $(REGISTRY)/warmer:latest -f deploy/Dockerfile --target kaniko-warmer .

.PHONY: push
push:
	@echo "Pushing Docker images..."
	docker push $(REGISTRY)/executor:latest
	docker push $(REGISTRY)/executor:debug
	docker push $(REGISTRY)/executor:slim
	docker push $(REGISTRY)/warmer:latest

# Code quality
.PHONY: install-tools lint check-all

install-tools:
	@echo "Installing development tools..."
	GOFLAGS="" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo "Development tools installed successfully"

lint: install-tools
	@if command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		echo "Running linter..."; \
		GOARCH=$(GOARCH) GOOS=$(GOOS) CGO_ENABLED=0 $(GOLANGCI_LINT) run --timeout=5m; \
		echo "Linter completed!"; \
	else \
		echo "golangci-lint is not installed. Installing..."; \
		GOFLAGS="" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; \
		echo "Running linter..."; \
		GOARCH=$(GOARCH) GOOS=$(GOOS) CGO_ENABLED=0 $(GOLANGCI_LINT) run --timeout=5m; \
		echo "Linter completed!"; \
	fi

check-all: lint
	@echo "All code quality checks completed"
