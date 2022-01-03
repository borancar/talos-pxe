.DEFAULT_GOAL := all
DOCKER := docker
TAG ?= $(shell cat VERSION)
PACKAGE ?= talos-pxe
TEST_PATTERN ?= "TestLogInfo"


.PHONY: unittest-local unittest build-unittest

build-unittest:
	$(DOCKER) build -t talos-pxe:unittest-${PACKAGE}-${TAG} --target unittest .
unittest-local:
	go test -cover -v ./... -coverprofile=out/coverage.out 2>&1 | tee out/unittest.out
	go tool cover -html=out/coverage.out -o out/coverage.html
unittest: build-unittest
	$(DOCKER) run -t -v ${PWD}:/go/src/github.com/borancar/talos-pxe \
	--rm  talos-pxe:unittest-${PACKAGE}-${TAG}
unittest-one: build-unittest
	$(DOCKER) run -t -v ${PWD}:/go/src/github.com/borancar/talos-pxe \
	--rm --entrypoint bash \
	talos-pxe:unittest-${PACKAGE}-${TAG} -c "go test -v -run $(TEST_PATTERN)"

