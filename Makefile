APPENV ?= testenv
PROJECT := hailcannon
GITCOMMIT := $(shell git rev-parse --short HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
 	GITCOMMIT := $(GITCOMMIT)-dirty
	endif

all: clean fmt build

clean:
	rm -fr target bin pkg

build:
	docker run \
		--env-file ./$(APPENV) \
		-e "TARGETS=linux/amd64"  \
		-e PROJECT=github.com/opsee/$(PROJECT) \
		-v `pwd`:/gopath/src/github.com/opsee/$(PROJECT) \
		quay.io/opsee/build-go:16 
	docker build -t quay.io/opsee/$(PROJECT):$(GITCOMMIT) .

run: $(APPENV)
	docker run \
	--env-file ./$(APPENV) \
	-e AWS_DEFAULT_REGION \
	-e AWS_ACCESS_KEY_ID \
	-e AWS_SECRET_ACCESS_KEY \
	-p 9109:9109 \
	--rm \
	quay.io/opsee/$(PROJECT):$(GITCOMMIT)

push:
	docker push quay.io/opsee/$(PROJECT):$(GITCOMMIT)

fmt:
	@gofmt -w .

.PHONY: all clean build run
