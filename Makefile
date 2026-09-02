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

.PHONY: install
install: build
	@sudo cp dist/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "✅ Installed to /usr/local/bin/$(BINARY)"

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

.PHONY: build-linux
build-linux:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o dist/$(BINARY)-linux-amd64 ./cmd/dsd
	@echo "✅ Built: dist/$(BINARY)-linux-amd64 ($(VERSION))"

# A reachable Linux host with passwordless sudo, for the deploy/run/root-test
# targets. No default — set it explicitly, e.g. `make deploy LINUX_HOST=root@10.0.0.5`.
# (The old hardcoded Legion box was retired; use any Linux guest you can SSH to.)
LINUX_HOST ?=
require-linux-host = @test -n "$(LINUX_HOST)" || { echo "✗ set LINUX_HOST=user@host (e.g. make $@ LINUX_HOST=root@10.0.0.5)"; exit 1; }

.PHONY: deploy
deploy: build-linux
	$(require-linux-host)
	scp dist/$(BINARY)-linux-amd64 $(LINUX_HOST):/tmp/dsd
	ssh $(LINUX_HOST) 'sudo -n install -m 755 /tmp/dsd /usr/bin/dsd && sudo -n install -m 755 /tmp/dsd /usr/local/bin/dsd && dsd --version'
	@echo "✅ Deployed to $(LINUX_HOST)"

# Run dsd as root on the remote host — needed for checks that require elevated
# access: /etc/shadow (user audit), IPMI sensors, auditd AVC log, hardware SMART.
.PHONY: run-root
run-root:
	$(require-linux-host)
	ssh $(LINUX_HOST) 'sudo -n /usr/bin/dsd $(ARGS)'

# Run the full Linux collector test suite as root on the remote host.
# Some collectors only produce full output under root (IPMI, auditd, /etc/shadow).
# For non-root linux-gated tests with no host, use `make test-linux` (Docker).
.PHONY: test-linux-root
test-linux-root:
	$(require-linux-host)
	@echo "→ Syncing source to $(LINUX_HOST):/tmp/dashdiag-test"
	rsync -a --exclude='.git' --exclude='dist/' . $(LINUX_HOST):/tmp/dashdiag-test/
	ssh $(LINUX_HOST) 'cd /tmp/dashdiag-test && sudo -n go test ./internal/collectors/ -v -count=1 -timeout 60s 2>&1'

# ── CODE QUALITY ──────────────────────────────────────────────────────────────
.PHONY: check
check: fmt-check vet lint

# NOT `gofmt -w .`/`gofmt -l .`: gofmt walks the raw filesystem with no
# .gitignore awareness, unlike `go vet ./...`/`go test ./...` below (module-
# scoped, skip dot-dirs automatically). On a dev machine with a populated
# .scratch/ (vendored module cache, scratch experiments) or nested
# .claude/worktrees/ (other concurrent worktrees, each its own git index),
# `-w .` would rewrite files it has no business touching -- silently
# corrupting another worktree's uncommitted state or a vendored module
# cache's checksummed contents. Scope to this repo's own tracked .go files.
.PHONY: fmt
fmt:
	gofmt -w $$(git ls-files -- '*.go')
	goimports -w $$(git ls-files -- '*.go') 2>/dev/null || true

.PHONY: fmt-check
fmt-check:
	@unformatted="$$(gofmt -l $$(git ls-files -- '*.go'))"; \
	if [ -n "$$unformatted" ]; then echo "❌ Files need formatting:"; echo "$$unformatted"; exit 1; fi
	@echo "✅ Format OK"

.PHONY: vet
vet:
	@go vet ./...
	@echo "✅ vet OK"

.PHONY: lint
lint:
	@golangci-lint run ./... 2>/dev/null || (echo "⚠️  golangci-lint not installed — run: make tools" && go vet ./...)

# lint-linux runs golangci-lint inside the dashdiag-dev OrbStack container so
# linux-only code paths (//go:build linux) are linted with the real linux tags.
# Use this before pushing when you've touched linux-only files.
.PHONY: lint-linux
lint-linux:
	docker run --rm \
		-v $(CURDIR):/src \
		-w /src \
		dashdiag-dev:latest \
		golangci-lint run ./...

.PHONY: license-check
license-check:
	@command -v go-licenses >/dev/null 2>&1 || { echo "⚠️  go-licenses not installed — run: make tools"; exit 0; }
	go-licenses check ./... --allowed_licenses=MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0

# ── TESTING ───────────────────────────────────────────────────────────────────
.PHONY: test
test:
	@echo "→ Unit tests (race detector)"
	go test -race -count=1 -timeout 300s ./...
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

.PHONY: test-fuzz test-fuzz-linux test-fuzz-all
# SSDLC Layer 2 (ADR-0007): per-release fuzzing of parsers, prioritised by
# THREAT_MODEL_CLI.md §5 (partially-attacker-influenced inputs). Does NOT hide
# failures — a crash or false-OK violation must fail the target (a fuzz run that
# swallows crashes is itself a false-OK). FUZZTIME overridable: make test-fuzz FUZZTIME=2m
#
# Targets are DISCOVERED (scripts/fuzz-discover.sh via `go list`+`go test
# -list`), never hardcoded here. A hardcoded list in this file once silently
# missed 18 of 44 real FuzzXxx functions for months, then — after a second
# hardcoded list (test-fuzz-linux) was bolted on next to it instead of
# replacing the pattern — a further 5 (docs/CONTINUOUS_FUZZING.md).
#
# test-fuzz / test-fuzz-linux keep their existing local meaning (the
# portable/macOS-safe subset vs. the //go:build linux subset); test-fuzz-all
# runs everything this host's toolchain can see (all 55 on Linux, the
# portable 24 on macOS — see scripts/fuzz-discover.sh's own header for why
# `all` still varies by host while `portable`/`linux` don't).
FUZZTIME ?= 30s
test-fuzz:
	@scripts/run-fuzz-targets.sh portable $(FUZZTIME)
test-fuzz-linux:
	@scripts/run-fuzz-targets.sh linux $(FUZZTIME)
test-fuzz-all:
	@scripts/run-fuzz-targets.sh all $(FUZZTIME)

.PHONY: test-contract
test-contract:
	go test -tags contract -count=1 ./test/contract/... 2>/dev/null || echo "⚠️  No contract tests yet"

.PHONY: test-linux
## Run the Linux-only collector tests (the *_linux.go files compile out on macOS)
## in a golang container — no remote host needed. Named volumes cache the build +
## module downloads so reruns are fast. Mirrors what CI runs on ubuntu.
DOCKER_GO ?= golang:1.26
test-linux:
	@echo "→ Running linux-gated collector tests in $(DOCKER_GO)"
	docker run --rm -v "$(CURDIR)":/src \
		-v dashdiag-gocache:/root/.cache/go-build -v dashdiag-gomod:/go/pkg/mod \
		-w /src $(DOCKER_GO) \
		sh -c 'go vet ./internal/collectors/ && go test -race -count=1 -timeout 120s ./internal/collectors/'

.PHONY: test-all
test-all: test test-integration test-contract

# ── BATCHED TEST ITERATION (host XProtect / thermal mitigation) ───────────────
## Compile-once-run-many, to stop the tight write→build→run loop from spraying
## fresh executables that macOS XProtect scans (sustained ~50% CPU + heat on the
## M-series Air — see CLAUDE.md "Test iteration cadence"). Compiles the package's
## test binary ONCE to .scratch/ (stable path → fewer new-inode scan events) and
## runs that artifact. Re-running without a source change re-executes the SAME
## binary — no recompile, nothing for XProtect to rescan.
##
##   make test-batch PKG=tips              # → ./internal/tips/...
##   make test-batch PKG=output RUN=Golden # filter to -test.run=Golden
##   make test-batch PKG=collectors ARGS='-test.count=5'
##
## Inside the dashdiag-dev container (Linux FS, XProtect-invisible) this simply
## runs the compiled binary too — no docker, no host-path dance. RTK is a
## context-trim proxy on the model transport and is orthogonal: it neither helps
## nor hinders this, so the target works identically with or without RTK.
PKG ?=
RUN ?=
.PHONY: test-batch
test-batch:
	@test -n "$(PKG)" || { echo "✗ set PKG=<pkg> (e.g. make test-batch PKG=tips)"; exit 1; }
	@mkdir -p .scratch
	@bin=.scratch/$(PKG).test; \
	newest=$$(find ./internal/$(PKG) -name '*.go' -newer "$$bin" 2>/dev/null | head -1); \
	if [ ! -f "$$bin" ] || [ -n "$$newest" ]; then \
		echo "→ Compiling ./internal/$(PKG)/... test binary once → $$bin"; \
		go test -c -o "$$bin" ./internal/$(PKG)/... || { echo "✗ compile failed"; exit 1; }; \
	else \
		echo "→ No source change — reusing $$bin (no recompile, no new scan event)"; \
	fi; \
	if [ ! -f "$$bin" ]; then echo "ℹ package has no test files — nothing to run"; exit 0; fi; \
	echo "→ Running $$bin$(if $(RUN), (-test.run=$(RUN)),)"; \
	"./$$bin" -test.v $(if $(RUN),-test.run=$(RUN),) $(ARGS)

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
# SSDLC Layer 1 (ADR-0007). Mirrors CI: gosec runs via golangci-lint (single
# source of truth for excludes — .golangci.yml); semgrep blocking set =
# ERROR+WARNING; the INFO rules are the periodic audit layer (run
# `make security-audit` to see them).
security: vuln
	@golangci-lint run --enable-only=gosec ./... && echo "gosec: clean" || true
	@semgrep scan --config .semgrep/ --error --severity ERROR --severity WARNING --quiet . 2>/dev/null && echo "semgrep (blocking set): clean" || echo "⚠️  semgrep findings or not installed — brew install semgrep"

.PHONY: security-audit
# Full semgrep output including non-blocking INFO audit rules
# (e.g. dsd-file-read-concat-path — review NEW hits, existing are audited).
security-audit:
	@semgrep scan --config .semgrep/ . 2>/dev/null || echo "⚠️  semgrep not installed — brew install semgrep"

# ── TOOLS ─────────────────────────────────────────────────────────────────────
.PHONY: tools
tools:
	@echo "→ Installing dev tools"
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/google/go-licenses@v1.6.0
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
	@echo "  make test-batch   → compile-once-run-many (PKG=tips [RUN=x]) — XProtect/heat mitigation"
	@echo "  make test-linux   → Linux-only collector tests in Docker (no host needed)"
	@echo "  make deploy       → build linux + deploy (set LINUX_HOST=user@host)"
	@echo "  make run-root     → run dsd as root on LINUX_HOST (ARGS='health --json')"
	@echo "  make test-linux-root → full collector tests as root on LINUX_HOST"
	@echo "  make golden-update→ update golden files"
	@echo "  make smoke        → smoke test (requires dsd in PATH)"
	@echo "  make vuln         → govulncheck"
	@echo "  make security     → govulncheck + gosec"
	@echo "  make tools        → install all dev tools"
	@echo "  make hooks        → install pre-commit and pre-push git hooks"
	@echo "  make clean        → remove dist/ and coverage files"


# Update embedded CVE snapshot from SUSE/RHEL OVAL feeds.
# Requires internet. Run before release to keep air-gapped data fresh.
update-cve-data:
	@echo "→ Updating embedded CVE snapshot..."
	@bash scripts/update-cve-data.sh
	@echo "→ Rebuild to embed: make release"

.PHONY: update-cve-data
