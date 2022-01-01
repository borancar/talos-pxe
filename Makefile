.DEFAULT_GOAL := all
DOCKER := docker
TAG ?= dev-build
PACKAGE ?= talos-pxe
GOTEST ?= go test

.PHONY: unittest-local unittest

unittest-local:
	$(GOTEST) -cover -v ./...
unittest:
	$(DOCKER) build -t talos-pxe:unittest-${PACKAGE}-${TAG} --target unittest .
	$(DOCKER) run -t --rm talos-pxe:unittest-${PACKAGE}-${TAG}
