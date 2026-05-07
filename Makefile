MODULE  := github.com/andreibeshkov/dashdiag
VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILT   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X '$(MODULE)/internal/version.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version.Built=$(BUILT)'

.PHONY: build check test clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/dsd ./cmd/dsd

check:
	go vet ./...
	gofmt -l .

test:
	go test -race -count=1 -timeout 60s ./...

clean:
	rm -rf dist/
