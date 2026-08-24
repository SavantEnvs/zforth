#!/usr/bin/env bash
#
# mayhem/build.sh — build zForth's fuzz harnesses + KAT oracle probe.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. Two targets:
#   fuzz_zf_eval       — feeds bytes as Forth SOURCE TEXT to zf_eval() (core.zf vocabulary
#                        preloaded from mayhem/generated/core_zf_data.h, embedded at commit time
#                        from forth/core.zf -- no filesystem access at fuzz time).
#   fuzz_zf_dict_load  — feeds bytes as a raw SAVED-DICTIONARY blob straight into ctx->dict,
#                        mirroring src/linux/main.c's `-l FILE` load() path (zf_dump() + a raw
#                        memcpy/fread, zero validation) -- a distinct attack surface from source
#                        text: word-lookup/dictionary-traversal over attacker-controlled bytes.
#
# Both are built THREE ways per target: (a) sanitized fuzzer binary, (b) sanitized standalone
# (non-fuzzer) reproducer via $STANDALONE_FUZZ_MAIN, and the project's own library is also built
# once more (c) completely CLEAN (no sanitizer, no DWARF pin) for mayhem/kat/zf_kat, the
# behavioral KAT oracle mayhem/test.sh runs.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

ZF_SRC="$SRC/src/zforth/zforth.c"
ZF_INC="-I$SRC/src/zforth -I$SRC/src/linux -I$SRC/mayhem"

# §6d / playbook §6: -fsanitize=fuzzer-no-link goes on the LIBRARY compile UNCONDITIONALLY (even
# when $SANITIZER_FLAGS is empty — the no-sanitizer build) so the fuzzed code itself carries SanCov
# instrumentation; $LIB_FUZZING_ENGINE alone only covers the harness translation unit.
#
# -fno-sanitize=float-cast-overflow: relax ONLY this one UBSan check, keep ASan + the rest of
# UBSan halting. Cause: dict_put_cell_typed() (zforth.c) does `unsigned int vi = v;` on a zf_cell
# (float) BEFORE checking its range -- converting a negative float to unsigned is undefined
# behavior by the C standard, and it fires on ANY negative literal being compiled into the
# dictionary. That includes upstream's OWN forth/core.zf (`: dec -1 swap +! ;`), which this
# harness loads on every single iteration to reach the language's real vocabulary -- so left
# halting, this one check aborts before a single fuzzed byte is even reached, on every run
# (verified empirically: only the size==0 fast-path input survived; every non-empty input hit
# this exact PC during core.zf's own bootstrap). Textbook case of the playbook's "a halting UBSan
# check can silently starve a target of coverage" -- confirmed the fix restores real exploration
# (fork-mode coverage climbs from a flat 0 well past 200 edges once relaxed).
ZF_SAN_FLAGS="$SANITIZER_FLAGS -fno-sanitize=float-cast-overflow"

$CC $ZF_SAN_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $ZF_INC \
    -c "$ZF_SRC" -o /tmp/zforth_fuzz.o

# libFuzzer harnesses + standalone reproducers.
for t in zf_eval zf_dict_load; do
  $CC $ZF_SAN_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $ZF_INC \
      "$SRC/mayhem/fuzz_${t}.c" /tmp/zforth_fuzz.o -lm \
      -o "/mayhem/fuzz_${t}"

  $CC $ZF_SAN_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main_${t}.o
  $CC $ZF_SAN_FLAGS $DEBUG_FLAGS $ZF_INC \
      /tmp/standalone_main_${t}.o "$SRC/mayhem/fuzz_${t}.c" /tmp/zforth_fuzz.o -lm \
      -o "/mayhem/fuzz_${t}-standalone"
done

# KAT oracle probe: CLEAN build — neither $SANITIZER_FLAGS nor $DEBUG_FLAGS (the oracle build must
# carry the project's normal flags so it stays an honest, independent functional check; it is
# also what makes it a genuine DYNAMICALLY LINKED binary the verify-repo sabotage shim can affect).
$CC -O2 $COVERAGE_FLAGS $ZF_INC -c "$ZF_SRC" -o /tmp/zforth_clean.o
# NOTE: output at the top-level /mayhem (== $SRC), matching the fuzz binaries above — NOT under
# $SRC/mayhem/kat/ (that's a source dir, mayhem/kat/zf_kat.c; $SRC itself is already "/mayhem", so
# a naive "/mayhem/kat/zf_kat" output path collides with nothing and just fails to link (no such
# directory) since only $SRC/mayhem/kat exists, not $SRC/kat).
$CC -O2 $COVERAGE_FLAGS $ZF_INC \
    "$SRC/mayhem/kat/zf_kat.c" /tmp/zforth_clean.o -lm \
    -o /mayhem/zf_kat

# Regression guard: the KAT probe MUST be dynamically linked (so the LD_PRELOAD sabotage shim in
# verify-repo's anti-reward-hack check can actually neuter it) — assert it unconditionally rather
# than trusting the default clang link behavior to stay that way.
file /mayhem/zf_kat | grep -q 'dynamically linked' || {
  echo "mayhem/zf_kat is NOT dynamically linked — the sabotage oracle check would be unaffected by it" >&2
  exit 1
}
