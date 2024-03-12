# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

MG_DOCKER_IMAGE_NAME_PREFIX ?= magistrala
SVC = ui
BUILD_DIR = build
CGO_ENABLED ?= 0
GOOS ?= linux
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags || echo "none")
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -ldflags "-s -w \
	-X 'github.com/absmach/magistrala.BuildTime=$(TIME)' \
	-X 'github.com/absmach/magistrala.Version=$(VERSION)' \
	-X 'github.com/absmach/magistrala.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/$(SVC) cmd/$(SVC)/main.go
endef

define make_docker
	docker build \
		--no-cache \
		--build-arg SVC=$(SVC) \
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg TIME=$(TIME) \
		--tag=$(MG_DOCKER_IMAGE_NAME_PREFIX)/$(SVC) \
		-f docker/Dockerfile .
endef

define make_docker_dev
	docker build \
		--no-cache \
		--build-arg SVC=$(SVC) \
		--tag=$(MG_DOCKER_IMAGE_NAME_PREFIX)/$(SVC) \
		-f docker/Dockerfile.dev .
endef

all: ui

.PHONY: ui docker docker_dev run_docker run

clean:
	rm -rf ${BUILD_DIR}

cleandocker:
	# Stops containers and removes containers, networks, volumes, and images created by up
	docker compose -f docker/docker-compose.yml --env-file docker/.env down -v

install:
	cp ${BUILD_DIR}/$(SVC) $(GOBIN)/magistrala-${SVC}

test:
	go test -v -race -count 1 -tags test $(shell go list ./... | grep -v 'cmd')

lint:
	golangci-lint run --config .golangci.yml
	npx prettier --config .prettierrc --plugin prettier-plugin-go-template --check .

$(SVC):
	$(call compile_service)

docker:
	$(call make_docker)

docker_dev:
	$(call make_docker_dev)

define docker_push
	docker push $(MG_DOCKER_IMAGE_NAME_PREFIX)/$(SVC):$(1)
endef

latest: docker
	$(call docker_push,latest)

run_docker:
	docker compose -f docker/docker-compose.yml --env-file docker/.env up

run:
	${BUILD_DIR}/$(SVC)
