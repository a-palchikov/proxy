
BUILDDIR ?= _build
VERSION ?= 1.0.0
GO_DOCKER_BASE ?= golang:1.22.1-bullseye
DOCKER_BASE ?= gcr.io/distroless/static-debian12

.PHONY: build
build: | $(BUILDDIR)
	go build -o $(BUILDDIR)/proxy ./...

.PHONY: image
image:
	docker buildx build \
		--file Dockerfile \
		--target releaser \
		--build-arg GO_DOCKER_BASE=$(GO_DOCKER_BASE) \
		--build-arg DOCKER_BASE=$(DOCKER_BASE) \
		--output type=image,name=$(REGISTRY)/$(REPOSITORY_NAMESPACE)/test-proxy:$(VERSION) \
		.

$(BUILDDIR):
	@mkdir $@
