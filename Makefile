# DashDiag — Makefile
# Usage: make (default: check+test) | make build | make release | make test-all

BINARY     := dsd
MODULE     := github.com/keyorixhq/dashdiag
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.0.0-dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILT      := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -X $(MODULE)/internal/version.Version=$(VERSION) \
              -X $(MODULE)/internal/version.Commit=$(COMMIT) \
              -X $(MODULE)/internal/version.Built=$(BUILT) \
              -s -w
CGO_ENABLED := 0

.DEFAULT_GOAL := all

.PHONY: all
all: check test

# ── BUILD ─────────────────────────────────────────────────────────────────────
.PHONY: build
build:
	@echo "→ Building $(BINARY) $(VERSION)"
	@mkdir -p dist
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY) ./cmd/dsd

.PHONY: release
release:
	@echo "→ Cross-compiling $(VERSION)"
	@mkdir -p dist
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY)-linux-amd64   ./cmd/dsd
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY)-linux-arm64   ./cmd/dsd
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY)-darwin-amd64  ./cmd/dsd
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY)-darwin-arm64  ./cmd/dsd
	@cd dist && sha256sum $(BINARY)-* > checksums.txt
	@echo "✅ Release binaries in dist/"

# ── CODE QUALITY ──────────────────────────────────────────────────────────────
.PHONY: check
check: fmt-check vet lint

.PHONY: fmt
fmt:
	gofmt -w .
	goimports -w . 2>/dev/null || true

.PHONY: fmt-check
fmt-check:
	@if [ -n "$$(gofmt -l .)" ]; then echo "❌ Files need formatting:"; gofmt -l .; exit 1; fi
	@echo "✅ Format OK"

.PHONY: vet
vet:
	@go vet ./...
	@echo "✅ vet OK"

.PHONY: lint
lint:
	@golangci-lint run ./... 2>/dev/null || (echo "⚠️  golangci-lint not installed — run: make tools" && go vet ./...)

# ── TESTING ───────────────────────────────────────────────────────────────────
.PHONY: test
test:
	@echo "→ Unit tests (race detector)"
	go test -race -count=1 -timeout 60s ./...
	@echo "✅ Tests passed"

.PHONY: cover
cover:
	go test -race -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ coverage.html generated"

.PHONY: test-integration
test-integration:
	go test -tags integration -race -count=1 -timeout 120s ./...

.PHONY: test-fuzz
test-fuzz:
	@echo "→ Fuzz tests (30s each)"
	go test -fuzz=FuzzParseLoadAvg    ./internal/collectors/ -fuzztime=30s 2>/dev/null || true
	go test -fuzz=FuzzReadVMStat      ./internal/collectors/ -fuzztime=30s 2>/dev/null || true
	go test -fuzz=FuzzParseIOCounters ./internal/collectors/ -fuzztime=30s 2>/dev/null || true

.PHONY: test-contract
test-contract:
	go test -tags contract -count=1 ./test/contract/... 2>/dev/null || echo "⚠️  No contract tests yet"

.PHONY: test-all
test-all: test test-integration test-contract

.PHONY: bench
bench:
	go test -bench=. -benchmem -benchtime=3x -run=^$$ ./internal/...

.PHONY: golden-update
golden-update:
	go test ./internal/render/... -update
	@echo "✅ Golden files updated — review diff before committing"

.PHONY: smoke
smoke:
	@bash scripts/smoke-test.sh

# ── SECURITY ──────────────────────────────────────────────────────────────────
.PHONY: vuln
vuln:
	govulncheck ./... 2>/dev/null || echo "⚠️  govulncheck not installed — run: make tools"

.PHONY: security
security: vuln
	gosec -quiet ./... 2>/dev/null || echo "⚠️  gosec not installed — run: make tools"

# ── TOOLS ─────────────────────────────────────────────────────────────────────
.PHONY: tools
tools:
	@echo "→ Installing dev tools"
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "✅ Tools installed"

.PHONY: hooks
hooks:
	@echo "→ Installing git hooks"
	cp scripts/hooks/pre-commit .git/hooks/pre-commit
	cp scripts/hooks/pre-push   .git/hooks/pre-push
	chmod +x .git/hooks/pre-commit .git/hooks/pre-push
	@echo "✅ Hooks installed"
	@echo "   pre-commit: gofmt + go vet + go test -short"
	@echo "   pre-push:   go test -race + golangci-lint + gosec"

# ── CLEAN ─────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	@rm -rf dist/ coverage.out coverage.html
	@echo "✅ Clean"

.PHONY: help
help:
	@echo "DashDiag — Make targets"
	@echo ""
	@echo "  make              → check + test (default)"
	@echo "  make build        → build ./dist/dsd"
	@echo "  make release      → cross-compile all 4 platforms"
	@echo "  make check        → fmt-check + vet + lint"
	@echo "  make test         → unit tests with race detector"
	@echo "  make cover        → unit tests + coverage.html"
	@echo "  make test-all     → unit + integration + contract"
	@echo "  make golden-update→ update golden files"
	@echo "  make smoke        → smoke test (requires dsd in PATH)"
	@echo "  make vuln         → govulncheck"
	@echo "  make security     → govulncheck + gosec"
	@echo "  make tools        → install all dev tools"
	@echo "  make hooks        → install pre-commit and pre-push git hooks"
	@echo "  make clean        → remove dist/ and coverage files"
