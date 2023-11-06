MF_DOCKER_IMAGE_NAME_PREFIX ?= magistrala
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
	-X 'github.com/absmach/magistrala-ui.BuildTime=$(TIME)' \
	-X 'github.com/absmach/magistrala-ui.Version=$(VERSION)' \
	-X 'github.com/absmach/magistrala-ui.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/magistrala-$(1) cmd/$(1)/main.go
endef

define make_docker
	$(eval svc=$(subst docker_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg TIME=$(TIME) \
		--tag=$(MF_DOCKER_IMAGE_NAME_PREFIX)/$(svc) \
		-f docker/Dockerfile .
endef

define make_docker_dev
	$(eval svc=$(subst docker_dev_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--tag=$(MF_DOCKER_IMAGE_NAME_PREFIX)/$(svc) \
		-f docker/Dockerfile.dev .
endef

all: ui

.PHONY: ui docker docker_dev

clean:
	rm -rf ${BUILD_DIR}

cleandocker:
	# Stops containers and removes containers, networks, volumes, and images created by up
	docker-compose -f docker/docker-compose.yml --env-file docker/.env down -v

install:
	cp ${BUILD_DIR}/* $(GOBIN)

test:
	GOCACHE=off go test -mod=vendor -v -race -count 1 -tags test $(shell go list ./... | grep -v 'vendor\|cmd')

lint:
	golangci-lint run --no-config --disable-all --enable gosimple --enable errcheck --enable govet --enable unused --enable goconst --enable godot --timeout 3m
	prettier --check --write ui

ui:
	$(call compile_service,$(@))

docker:
	$(call make_docker,ui)

docker_dev:
	$(call make_docker_dev,ui)

run_docker:
	docker-compose -f docker/docker-compose.yml --env-file docker/.env up

run:
	${BUILD_DIR}/magistrala-ui
