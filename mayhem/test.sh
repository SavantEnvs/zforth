#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the behavioral KAT oracle built by mayhem/build.sh (/mayhem/zf_kat, from
# source mayhem/kat/zf_kat.c).
#
# zForth ships no unit-test framework of its own, so the oracle is a small dynamically-linked
# probe (mayhem/kat/zf_kat.c) that boots the REAL interpreter (zf_bootstrap + forth/core.zf,
# embedded verbatim), evaluates a handful of deterministic Forth programs through the real
# zf_eval() entry point, and asserts EXACT output for each — including upstream's own
# forth/misc.zf `fib` word run verbatim (a 43-term Fibonacci sequence via `begin...until`).
# A neutered/no-op binary (verify-repo's sabotage shim _exit(0)s any non-system executable before
# it runs) produces empty/short-circuited output and fails every assertion below — this is a
# behavioral oracle, not an exit-code/liveness check.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN=/mayhem/zf_kat
if [ ! -x "$BIN" ]; then
  echo "missing $BIN — run mayhem/build.sh first" >&2
  emit_ctrf "zf-kat" 0 1
  exit 1
fi

# Unconditional: no [ -f seed ] guard — a missing/neutered binary already fails above; a garbled
# or empty run below is a FAILURE, never a skip.
out="$("$BIN" 2>&1)"; rc=$?
echo "$out"

# Parse the probe's own "KAT summary: N run, F failed" line. Its absence (empty/neutered output)
# means the probe never actually ran its checks — treat as one failed test, not zero tests.
if summary="$(printf '%s\n' "$out" | grep -oE 'KAT summary: [0-9]+ run, [0-9]+ failed' | tail -1)" \
   && [ -n "$summary" ]; then
  total="$(printf '%s' "$summary" | sed -E 's/KAT summary: ([0-9]+) run.*/\1/')"
  failed="$(printf '%s' "$summary" | sed -E 's/.*, ([0-9]+) failed/\1/')"
else
  total=1; failed=1
fi

# Belt-and-suspenders: a nonzero exit code, or a missing golden value from the fib_upstream_fixture
# check (forth/misc.zf's own `fib` word run verbatim through zf_eval), each also counts as a
# failure even if the summary line above somehow looked clean.
if [ "$rc" -ne 0 ]; then
  [ "$failed" -gt 0 ] || failed=1
fi
if ! printf '%s\n' "$out" | grep -qF '9227465 14930352 24157816'; then
  failed=$(( failed + 1 )); total=$(( total + 1 ))
fi

passed=$(( total - failed ))
[ "$passed" -ge 0 ] || passed=0

emit_ctrf "zf-kat" "$passed" "$failed"
