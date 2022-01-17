SHELL := /bin/bash
.DEFAULT_GOAL := all
DOCKER := docker
TAG ?= $(shell cat VERSION)
PACKAGE ?= talos-pxe
TEST_PATTERN ?= "TestLogInfo"
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
THIS_FILE := $(lastword $(MAKEFILE_LIST))


.PHONY: unittest-local unittest build-unittest all

all:
	$(info Currently the make is used only for running tests)
	@$(MAKE) -f $(THIS_FILE) unittest

build-unittest:
	$(DOCKER) build -t talos-pxe:unittest-${PACKAGE}-${TAG} --target unittest .
unittest-local:
    # we want the test output in file by tee but also the exit status to fail on test failure hence the set -o pipefail
	set -o pipefail; go test -cover -v ./... -coverprofile=out/coverage.out 2>&1 | tee out/unittest.out
	go tool cover -html=out/coverage.out -o out/coverage.html
unittest: build-unittest
	$(DOCKER) run -t -v ${ROOT_DIR}:/go/src/github.com/borancar/talos-pxe \
	--rm  talos-pxe:unittest-${PACKAGE}-${TAG}
unittest-one: build-unittest
	$(DOCKER) run -t -v ${ROOT_DIR}:/go/src/github.com/borancar/talos-pxe \
	--rm --entrypoint bash \
	talos-pxe:unittest-${PACKAGE}-${TAG} -c "go test -v -run $(TEST_PATTERN)"

