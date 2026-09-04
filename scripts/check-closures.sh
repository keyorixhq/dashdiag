#!/bin/bash
# check-closures.sh — fails if any product-claim closure recorded in the ledger
# lacks a proving test that actually runs and passes.
#
# Ported from Keyorix's scripts/check-closures.sh (same org, same failure shape:
# a claim recorded as "fixed" that nobody re-verified by running anything).
# DashDiag has no authz layer, so this ledger isn't about security closures —
# it's about the false-OK / wrong-claim bug class BUGS.md already tracks: a
# status the product reports that the code doesn't actually establish. Same
# fix shape as GAP-1/GAP-2 in docs/product-claim-gaps-2026-09-02.md.
#
# Two design rules, each from a failure (Keyorix's, ported because they apply
# here unchanged):
#
#   1. Verify by test, not by commit. This repo squash-merges (CLAUDE.md's
#      merge step is `gh pr merge --squash --delete-branch --admin`), so
#      `git merge-base --is-ancestor <branch> main` returns false for every
#      correctly landed PR — a check that always fails is as useless as one
#      that always passes, and more corrosive, because it teaches people to
#      ignore it. The landed_commit column is informational only.
#
#   2. PASS is not "did not fail". `go test -run` over a name that matches
#      nothing EXITS ZERO, and a skipped test does not appear as SKIP at all
#      without -v. So this requires a literal `--- PASS: <name>` line and
#      reports SKIP, no-match, and unrecognised output as three distinct
#      failures.
#
# DashDiag-specific caveat (no equivalent in Keyorix, which has no per-OS
# build tags on its proving tests): several proving tests below live in
# `//go:build linux` (or `darwin`) files. `go test -run X` over a package whose
# only matching test file is excluded by GOOS returns exit 0 with "no tests to
# run" — indistinguishable, from this script's point of view, from a renamed
# or deleted test. That's rule 2's exact failure shape, just triggered by a
# build tag instead of a runtime skip. This script does not special-case it:
# run it on the GOOS the ledger row's test actually requires. CI wires it into
# ubuntu-24.04 jobs (ci.yml), so linux-gated rows verify correctly there. A
# local run on macOS will report a false FAIL for any linux-gated proving test
# — use the dashdiag-dev container, or the golang:1.26 Docker recipe in
# CLAUDE.md's containerized-Linux-tests section, for an honest local result.
#
# Usage:
#   ./scripts/check-closures.sh              # verify every row in the ledger
#   ./scripts/check-closures.sh --self-test  # prove the check can go red
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="${CLOSURE_LEDGER:-$REPO_ROOT/docs/product-closures.tsv}"
fail=0
checked=0
die()  { echo "FAIL: $*" >&2; fail=1; }
note() { echo "  $*"; }

if [ ! -f "$LEDGER" ]; then
    echo "FAIL: closure ledger not found at $LEDGER" >&2; exit 1
fi

rows=$(grep -vE '^[[:space:]]*(#|$)' "$LEDGER" || true)
if [ -z "$rows" ]; then
    echo "FAIL: closure ledger is empty — a ledger with no rows cannot fail, and" >&2
    echo "      a check that cannot fail is not a check." >&2
    exit 1
fi

dupes=$(cut -f1 <<<"$rows" | sort | uniq -d || true)
if [ -n "$dupes" ]; then
    die "duplicate claim_id in ledger:"; for d in $dupes; do note "$d"; done
fi

while IFS=$'\t' read -r claim pkg test commit rest; do
    [ -z "${claim:-}" ] && continue
    if [ -z "${pkg:-}" ] || [ -z "${test:-}" ]; then
        die "$claim: missing package or proving_test — a closure without a citation is not a closure"
    fi
    [ -z "${commit:-}" ] && die "$claim: missing landed_commit"
done <<<"$rows"
[ "$fail" -eq 0 ] || exit 1

mapfile -t pkgs < <(cut -f2 <<<"$rows" | sort -u)
for pkg in "${pkgs[@]}"; do
    tests=$(awk -F'\t' -v p="$pkg" '$2==p {print $3}' <<<"$rows")
    pattern=$(paste -sd'|' - <<<"$tests")
    echo "==> $pkg"
    set +e
    out=$(cd "$REPO_ROOT" && go test -count=1 -v -run "^(${pattern})\$" "$pkg" 2>&1); rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        die "$pkg: go test exited $rc"; sed -n '1,40p' <<<"$out" | sed 's/^/      /'; continue
    fi
    while IFS= read -r test; do
        [ -z "$test" ] && continue
        checked=$((checked + 1))
        claim=$(awk -F'\t' -v p="$pkg" -v t="$test" '$2==p && $3==t {print $1}' <<<"$rows")
        if grep -qE "^--- PASS: ${test}([[:space:]]|$)" <<<"$out"; then
            note "ok   $claim -> $test"
        elif grep -qE "^--- SKIP: ${test}([[:space:]]|$)" <<<"$out"; then
            die "$claim: proving test $test SKIPPED, not passed."
            note "     A skipped test proves nothing. If it needs a build tag or fixture,"
            note "     CI must supply it, or this closure has no evidence."
        elif grep -q "no tests to run" <<<"$out"; then
            die "$claim: proving test $test DOES NOT EXIST (go test matched nothing, exited 0)."
            note "     The false-green case: a renamed, deleted or never-written test"
            note "     still reports success. If this test is GOOS-gated, confirm you're"
            note "     running on the OS it requires (see this script's header)."
        else
            die "$claim: proving test $test produced no PASS line and no recognised failure."
            sed -n '1,20p' <<<"$out" | sed 's/^/      /'
        fi
    done <<<"$tests"
done

if [ "${1:-}" = "--self-test" ]; then
    echo; echo "==> self-test: the check must reject a closure naming a nonexistent test"
    tmp=$(mktemp)
    printf 'SELF-TEST\t./internal/analysis\tTestThisNameDoesNotExistAnywhere\tdeadbeef\tcalibration row\n' > "$tmp"
    set +e
    CLOSURE_LEDGER="$tmp" "$0" >/dev/null 2>&1; selfrc=$?
    set -e
    rm -f "$tmp"
    if [ "$selfrc" -eq 0 ]; then
        echo "FAIL: self-test PASSED when it must fail — this check cannot detect a" >&2
        echo "      missing proving test and is therefore worthless." >&2
        exit 1
    fi
    echo "  ok: self-test correctly went red (exit $selfrc)"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "ok: $checked closure claim(s) verified — each names a test that ran and passed"
else
    echo "CLOSURE VERIFICATION FAILED — do not treat the ledger as accurate" >&2; exit 1
fi
