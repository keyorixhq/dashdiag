# syntax=docker/dockerfile:1

# dsd's own product identity (CLAUDE.md constraint #6: "single static binary,
# zero runtime deps") applies to the image too — CGO_ENABLED=0, no shell, no
# package manager in the final stage. The container image is a distribution
# vehicle for that binary, not a runtime environment it depends on.

# ── build stage ───────────────────────────────────────────────────────────
# Pinned by digest, not just the floating "1.26" tag ci.yml/release.yml use
# for setup-go — a tag can move underneath a cached build; a digest can't.
# Re-pin deliberately (not automatically) alongside the next Go version bump,
# same cadence as every other pinned-by-digest tool in this repo.
#
# --platform=$BUILDPLATFORM: always run the Go toolchain on the BUILDER's
# native arch (the release runner is amd64), even when TARGETARCH below is
# arm64 — `go build` cross-compiles via GOOS/GOARCH natively, no QEMU needed
# for compiling. The final stage below has no RUN steps at all, so it never
# needs emulation either — the net effect is this Dockerfile builds both
# linux/amd64 and linux/arm64 under buildx with ZERO QEMU-emulated execution,
# only a metadata-level platform pull for the distroless base and a plain
# COPY for the cross-compiled binary.
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:6c2a5538f964f1c82f97ad14988bf05de100d922d159d0e398b54c7b0ca0c6c9 AS build

WORKDIR /src

# Cache module downloads separately from source so an unrelated source edit
# doesn't invalidate the (slow) download layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG BUILT=unknown

ENV CGO_ENABLED=0
# Same -ldflags shape as Makefile/release.yml (VERSION/COMMIT/BUILT injected
# into internal/version) — `dsd --version` must report the real release
# version inside the image, not "dev", and must match across every
# distribution channel (binary, .deb/.rpm, AppImage, image).
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags "-X github.com/keyorixhq/dashdiag/internal/version.Version=${VERSION} -X github.com/keyorixhq/dashdiag/internal/version.Commit=${COMMIT} -X github.com/keyorixhq/dashdiag/internal/version.Built=${BUILT} -s -w" \
      -trimpath -o /out/dsd ./cmd/dsd

# ── final stage ───────────────────────────────────────────────────────────
# distroless "static" (not "base"): CGO_ENABLED=0 means dsd links no libc, so
# `base`'s glibc/openssl userland would be dead weight and unused attack
# surface. The "nonroot" variant (not bare `scratch`): it ships a minimal
# /etc/passwd/group with a real, non-zero UID (65532) and a HOME dir — dsd's
# own read-only-self-diagnosis promise (never writes to the host) holds
# either way, but the "nonroot" tag makes that a property of who the process
# runs as, not just of what dsd chooses to do, and gives self-update/baseline
# code a resolvable $HOME instead of none. Pinned by digest for the same
# reproducibility reason as the build stage above.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG COMMIT=none

# org.opencontainers.* — standard OCI annotations (source/version/revision/
# licenses/description) any registry or `docker inspect` understands.
# io.modelcontextprotocol.server.name — the MCP Registry's OCI ownership-proof
# label; its value MUST match server.json's top-level "name" exactly, or
# registry publish validation for the oci package entry fails.
LABEL org.opencontainers.image.source="https://github.com/keyorixhq/dashdiag" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Read-only Linux/macOS system health diagnosis — one command, full picture. No agent, no cloud, no writes to the host." \
      io.modelcontextprotocol.server.name="io.github.keyorixhq/dashdiag"

COPY --from=build /out/dsd /usr/local/bin/dsd

USER nonroot
ENTRYPOINT ["dsd"]
CMD ["health"]
