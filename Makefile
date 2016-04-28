PROJECT := github.com/opsee/hailcannon

# docker tag is HAILCANNON_VERSION unless HAILCANNON_VERSION is set
HAILCANNON_VERSION := $(shell git rev-parse --short HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
	GITCOMMIT := $(HAILCANNON_VERSION)-dirty
endif

all: clean fmt build

clean:
	rm -fr target bin pkg

build:
	docker run \
	-e AWS_DEFAULT_REGION \
	-e "TARGETS=linux/amd64"  \
	-e PROJECT=$(PROJECT) \
	-v `pwd`:/gopath/src/$(PROJECT) \
	quay.io/opsee/build-go:16
	docker build -t quay.io/opsee/hailcannon:${HAILCANNON_VERSION} .

docker-push:
	docker push quay.io/opsee/hailcannon:${HAILCANNON_VERSION} 

fmt:
	@gofmt -w .

.PHONY: clean all
.PHONY: $(BINARIES)
.PHONY: $(CMDS)
