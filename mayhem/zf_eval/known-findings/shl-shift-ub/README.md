# shl-shift-ub — unchecked shift amount in PRIM_SHL / PRIM_SHR

**Cause:** `src/zforth/zforth.c`, `run()`'s primitive switch:

```c
case PRIM_SHL:
    d1 = zf_pop(ctx);
    zf_push(ctx, (zf_int)zf_pop(ctx) << (zf_int)d1);
    break;

case PRIM_SHR:
    d1 = zf_pop(ctx);
    zf_push(ctx, (zf_int)zf_pop(ctx) >> (zf_int)d1);
    break;
```

The `<<`/`>>` words (`zforth.c` primitive names `<<`/`>>`) shift by a value popped straight off
the data stack with no range check. `zf_int` is a 32-bit `int` (`src/linux/zfconf.h`), so a shift
amount outside `[0, 31]` is undefined behavior per C (UBSan: "shift exponent N is too large for
32-bit type"). Any Forth program can trigger it directly — no core.zf vocabulary needed, since
`<<`/`>>` are raw primitives.

**Impact:** undefined behavior (UBSan-detected here; on some platforms/compilers this can also
misbehave at runtime rather than just being caught by the sanitizer). Not memory corruption by
itself, but a real correctness/robustness bug in the interpreter core reachable from untrusted
Forth source.

**Repro:** `repro.zf` — `1 32 <<` (shift by 32, one past the 32-bit width).

```
$ /mayhem/fuzz_zf_eval-standalone mayhem/zf_eval/known-findings/shl-shift-ub/repro.zf
zforth.c:787:37: runtime error: shift exponent 32 is too large for 32-bit type 'zf_int' (aka 'int')
```

**One-line upstream fix:** mask/clamp the shift amount before use, e.g.
`(zf_int)zf_pop(ctx) << ((zf_int)d1 & 31)` (and the `zf_int)d1 & 31` equivalent for `>>`), or
`zf_abort(ctx, ZF_ABORT_INVALID_SIZE)` when `d1` is outside `[0, 31]`.

**Fuzzing note:** left UNGUARDED in the harness on purpose (per the playbook: don't mask real
bugs). Confirmed empirically in fork-mode retesting that coverage keeps climbing well past this
finding (192 -> 200+ edges across repeated hits), so it does not starve the target of coverage —
it is a normal "found a bug, fuzzer keeps going" case, not an always-crasher.
