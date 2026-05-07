#!/bin/bash
# scripts/smoke-test.sh
# Run after building: bash scripts/smoke-test.sh
# Requires: dist/dsd binary built (make build)

set -e
BINARY="./dist/dsd"
PASS=0; FAIL=0

check() {
    local desc=$1; shift
    if "$@" >/dev/null 2>&1; then
        echo "✅ $desc"; ((PASS++))
    else
        echo "❌ $desc"; ((FAIL++))
    fi
}

echo "→ DashDiag smoke tests"
echo ""

check "binary exists"                    test -f "$BINARY"
check "dsd --version exits 0"            $BINARY --version
check "dsd --help exits 0"              $BINARY --help
check "dsd health exits 0 or 1"         bash -c "$BINARY health; [ \$? -le 1 ]"
check "dsd health --json valid JSON"    bash -c "$BINARY health --json | python3 -m json.tool"
check "dsd health --plain no ANSI"      bash -c "$BINARY health --plain | grep -qv $'\\033'"
check "dsd health --diff no crash"      bash -c "$BINARY health --diff; [ \$? -le 2 ]"
check "typo suggests correct command"   bash -c "$BINARY healt 2>&1 | grep -q health"
check "dsd examples exits 0"           bash -c "$BINARY examples; [ \$? -eq 0 ]" 2>/dev/null || true

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
