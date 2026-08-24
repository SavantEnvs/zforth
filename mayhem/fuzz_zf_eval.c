/*
 * mayhem/fuzz_zf_eval.c — libFuzzer harness for zForth's zf_eval() entry point.
 *
 * Feeds arbitrary fuzzer bytes as Forth SOURCE TEXT to zf_eval(). To reach anything beyond
 * the raw primitive words, we first zf_eval() zForth's own forth/core.zf vocabulary (`.`,
 * `if`/`else`/`fi`, `begin`/`until`, `s"`/`."`, `variable`, `do`/`loop`, ...) -- embedded at
 * BUILD time as a byte array (mayhem/generated/core_zf_data.h, produced by build.sh from the
 * upstream file). This is the same bootstrap the CLI does via `./zforth forth/core.zf`
 * (see src/linux/main.c's `include()`), just fed as bytes instead of a file read, so the
 * harness never touches the filesystem at fuzz time (only fuzzer-provided bytes are consumed
 * per iteration).
 *
 * A compiled zForth word using `begin ... again` can loop forever in run(); that is a hang
 * finding, bounded per exec by the Mayhemfile `timeout:` and libFuzzer's own -timeout -- the
 * harness arms no timer of its own.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zforth.h"

#include "generated/core_zf_data.h"

/* -------- host callbacks required by the zForth API (no I/O, no filesystem) -------- */

zf_input_state zf_host_sys(zf_ctx *ctx, zf_syscall_id id, const char *input)
{
	(void)input;
	switch ((int)id) {
	case ZF_SYSCALL_EMIT:
		zf_pop(ctx);
		break;
	case ZF_SYSCALL_PRINT:
		zf_pop(ctx);
		break;
	case ZF_SYSCALL_TELL: {
		zf_cell len = zf_pop(ctx);
		zf_cell addr = zf_pop(ctx);
		(void)len;
		(void)addr;
		break;
	}
	default:
		/* application-specific syscalls (sin, include, save, quit, ...): no-op.
		 * Deliberately do NOT implement ZF_SYSCALL_USER+0 (quit -> exit(0) in the
		 * reference main.c) -- that would terminate the whole fuzzing process. */
		break;
	}
	return ZF_INPUT_INTERPRET;
}

void zf_host_trace(zf_ctx *ctx, const char *fmt, va_list va)
{
	(void)ctx;
	(void)fmt;
	(void)va;
}

zf_cell zf_host_parse_num(zf_ctx *ctx, const char *buf)
{
	zf_cell v;
	int n = 0;
	int r = sscanf(buf, ZF_SCAN_FMT "%n", &v, &n);
	if (r != 1 || buf[n] != '\0') {
		zf_abort(ctx, ZF_ABORT_NOT_A_WORD);
	}
	return v;
}

/* -------- the harness itself -------- */

#define ZF_FUZZ_MAX_INPUT 4096

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char buf[ZF_FUZZ_MAX_INPUT + 1];
	static zf_ctx ctx;

	if (size == 0 || size > ZF_FUZZ_MAX_INPUT) {
		return 0;
	}
	memcpy(buf, data, size);
	buf[size] = '\0';
	/* zf_eval() runs line-oriented via handle_char(); embedded NULs in the fuzzer input
	 * would just end the C string early via strchr-style scanning above -- harmless, just
	 * truncates this iteration's source text. */

	memset(&ctx, 0, sizeof(ctx));
	zf_init(&ctx, 0 /* trace off */);
	zf_bootstrap(&ctx);

	/* Load the core vocabulary (defines `.`, `if`/`fi`, `begin`/`until`, `s"`,
	 * `variable`, `do`/`loop`, ...) so fuzzed input can reach far more of the
	 * interpreter than the dozen raw primitives alone. */
	zf_eval(&ctx, zf_core_src);
	zf_eval(&ctx, buf);

	return 0;
}
