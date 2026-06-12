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

.PHONY: deploy
LEGION_HOST ?= andrei@192.168.1.145
deploy: build-linux
	scp dist/$(BINARY)-linux-amd64 $(LEGION_HOST):/tmp/dsd
	ssh $(LEGION_HOST) 'sudo -n install -m 755 /tmp/dsd /usr/bin/dsd && sudo -n install -m 755 /tmp/dsd /usr/local/bin/dsd && dsd --version'
	@echo "✅ Deployed to $(LEGION_HOST)"

# Run dsd as root on Legion — needed for checks that require elevated access:
# /etc/shadow (user audit), IPMI sensors, auditd AVC log, hardware SMART writes.
.PHONY: run-root
run-root:
	ssh $(LEGION_HOST) 'sudo -n /usr/bin/dsd $(ARGS)'

# Run the full Linux test suite on Legion as root.
# Some collectors only produce full output under root (IPMI, auditd, /etc/shadow).
.PHONY: test-linux-root
test-linux-root:
	@echo "→ Syncing source to $(LEGION_HOST):/tmp/dashdiag-test"
	rsync -a --exclude='.git' --exclude='dist/' . $(LEGION_HOST):/tmp/dashdiag-test/
	ssh $(LEGION_HOST) 'cd /tmp/dashdiag-test && sudo -n env GOROOT=/home/andrei/go GOPATH=/home/andrei/gopath /home/andrei/go/bin/go test ./internal/collectors/ -v -count=1 -timeout 60s 2>&1'

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
# SSDLC Layer 2 (ADR-0007): per-release fuzzing of parsers, prioritised by
# THREAT_MODEL_CLI.md §5 (partially-attacker-influenced inputs). Does NOT hide
# failures — a crash or false-OK violation must fail the target (a fuzz run that
# swallows crashes is itself a false-OK). FUZZTIME overridable: make test-fuzz FUZZTIME=2m
FUZZTIME ?= 30s
test-fuzz:
	@echo "→ Fuzz tests ($(FUZZTIME) each) — Ctrl-C to stop early"
	@set -e; \
	go test -run=NONE -fuzz='^FuzzParseLoadAvg$$'        -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseMeminfo$$'        -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseVMStat$$'         -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseDiskstats$$'      -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseFileNr$$'         -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseProcStat$$'       -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseVGs$$'            -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseLVs$$'            -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseLVMFloat$$'       -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseSteamOSChannel$$' -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseHealth$$'         -fuzztime=$(FUZZTIME) ./internal/fleet/; \
	go test -run=NONE -fuzz='^FuzzParseProcStatComm$$'   -fuzztime=$(FUZZTIME) ./internal/drilldown/; \
	go test -run=NONE -fuzz='^FuzzParseMountFromMessage$$' -fuzztime=$(FUZZTIME) ./internal/drilldown/; \
	go test -run=NONE -fuzz='^FuzzParseUnitFromMessage$$' -fuzztime=$(FUZZTIME) ./internal/drilldown/
	@echo "✅ all portable fuzz harnesses passed"
	@echo "→ Linux-only parser harnesses (skipped on $(shell go env GOOS)):"
	@echo "   FuzzParseMDStat, FuzzParseNVMeSmartLog, FuzzParseLVMRaid — run on Linux/CI"

.PHONY: test-fuzz-linux
# Linux-tagged parser harnesses (raid_linux/nvme_linux/lvm_linux). Run on a
# Linux host or in CI; they don't compile on macOS by design.
test-fuzz-linux:
	@set -e; \
	go test -run=NONE -fuzz='^FuzzParseMDStat$$'        -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseNVMeSmartLog$$'  -fuzztime=$(FUZZTIME) ./internal/collectors/; \
	go test -run=NONE -fuzz='^FuzzParseLVMRaid$$'       -fuzztime=$(FUZZTIME) ./internal/collectors/
	@echo "✅ all Linux fuzz harnesses passed"

.PHONY: test-contract
test-contract:
	go test -tags contract -count=1 ./test/contract/... 2>/dev/null || echo "⚠️  No contract tests yet"

.PHONY: test-linux
## Run Linux-only collector tests on the Legion box via SSH.
## Uses the same LEGION_HOST as `make deploy` (default: andrei@192.168.1.145).
## Requires Go installed on the remote host.
test-linux:
	@echo "→ Syncing source to $(LEGION_HOST):/tmp/dashdiag-test"
	rsync -a --exclude='.git' --exclude='dist/' . $(LEGION_HOST):/tmp/dashdiag-test/
	ssh $(LEGION_HOST) 'cd /tmp/dashdiag-test && GOROOT=/home/andrei/go GOPATH=/home/andrei/gopath /home/andrei/go/bin/go test ./internal/collectors/ -run "TestParseVGs|TestParseLVs|TestMergeMissingPVs" -v'

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
	@echo "  make deploy       → build linux + deploy to Legion via SSH"
	@echo "  make run-root     → run dsd as root on Legion (ARGS='health --json')"
	@echo "  make test-linux   → Linux-only collector tests via SSH to Legion"
	@echo "  make test-linux-root → full collector tests as root on Legion"
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
