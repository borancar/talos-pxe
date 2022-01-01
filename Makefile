.DEFAULT_GOAL := all
DOCKER := docker
TAG ?= $(shell cat VERSION)
PACKAGE ?= talos-pxe

.PHONY: unittest-local unittest

unittest-local:
	go test -cover -v ./... -coverprofile=out/coverage.out 2>&1 | tee out/unittest.out
	go tool cover -html=out/coverage.out -o out/coverage.html
unittest:
	$(DOCKER) build -t talos-pxe:unittest-${PACKAGE}-${TAG} --target unittest .
	$(DOCKER) run -t -v ${PWD}:/go/src/github.com/borancar/talos-pxe --rm  talos-pxe:unittest-${PACKAGE}-${TAG}
