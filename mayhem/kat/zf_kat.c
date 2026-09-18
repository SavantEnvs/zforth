/*
 * mayhem/kat/zf_kat.c — behavioral known-answer oracle for mayhem/test.sh.
 *
 * A dynamically-linked binary (default clang link, no static linking) that boots zForth
 * (bootstrap + the real forth/core.zf vocabulary, embedded at build time -- same bytes
 * fuzz_zf_eval.c uses), evaluates a handful of small deterministic Forth programs through the
 * REAL zf_eval() entry point, captures the interpreter's own output via the zf_host_sys()
 * ZF_SYSCALL_EMIT/PRINT/TELL callbacks, and asserts each result against an exact expected
 * value. A no-op/neutered binary (verify-repo's sabotage shim _exit(0)s it before any of this
 * runs) fails every assertion below and returns non-zero -- this is a behavioral oracle, not an
 * exit-code/liveness check.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zforth.h"
#include "generated/core_zf_data.h"

static char capture[4096];
static size_t capture_len;

static void cap_reset(void) { capture_len = 0; capture[0] = '\0'; }

static void cap_append(const char *p, size_t n)
{
	if (capture_len + n >= sizeof(capture)) {
		n = sizeof(capture) - 1 - capture_len;
	}
	memcpy(capture + capture_len, p, n);
	capture_len += n;
	capture[capture_len] = '\0';
}

zf_input_state zf_host_sys(zf_ctx *ctx, zf_syscall_id id, const char *input)
{
	(void)input;
	switch ((int)id) {
	case ZF_SYSCALL_EMIT: {
		char c = (char)zf_pop(ctx);
		cap_append(&c, 1);
		break;
	}
	case ZF_SYSCALL_PRINT: {
		char tmp[64];
		int n = snprintf(tmp, sizeof(tmp), ZF_CELL_FMT " ", zf_pop(ctx));
		if (n > 0) cap_append(tmp, (size_t)n);
		break;
	}
	case ZF_SYSCALL_TELL: {
		zf_cell len = zf_pop(ctx);
		zf_cell addr = zf_pop(ctx);
		size_t dump_len;
		uint8_t *base = (uint8_t *)zf_dump(ctx, &dump_len);
		if (addr < 0 || len < 0 || (size_t)addr + (size_t)len > dump_len) {
			zf_abort(ctx, ZF_ABORT_OUTSIDE_MEM);
		}
		cap_append((const char *)(base + (size_t)addr), (size_t)len);
		break;
	}
	default:
		break;
	}
	return ZF_INPUT_INTERPRET;
}

void zf_host_trace(zf_ctx *ctx, const char *fmt, va_list va) { (void)ctx; (void)fmt; (void)va; }

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

static int checks_run = 0;
static int checks_failed = 0;

static void check(zf_ctx *ctx, const char *name, const char *src, const char *expect)
{
	zf_result r;

	checks_run++;
	cap_reset();
	r = zf_eval(ctx, src);
	if (r != ZF_OK) {
		fprintf(stderr, "FAIL %s: zf_eval() returned %d, expected ZF_OK(0) -- src=%s\n",
		        name, (int)r, src);
		checks_failed++;
		return;
	}
	if (strcmp(capture, expect) != 0) {
		fprintf(stderr, "FAIL %s: got %s expected %s -- src=%s\n",
		        name, capture, expect, src);
		checks_failed++;
		return;
	}
	printf("PASS %s: %s => %s\n", name, src, capture);
}

int main(void)
{
	zf_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	zf_init(&ctx, 0);
	zf_bootstrap(&ctx);
	if (zf_eval(&ctx, zf_core_src) != ZF_OK) {
		fprintf(stderr, "FAIL bootstrap: loading forth/core.zf itself did not return ZF_OK\n");
		return 1;
	}

	/* Known-answer checks through the real interpreter: arithmetic, a user-defined word, a
	 * conditional, string output, and upstream's OWN forth/misc.zf `fib` word run verbatim
	 * (Fibonacci via `begin ... until`, terminating once a term exceeds 1e9) -- each asserts
	 * an EXACT value. */
	check(&ctx, "arith_add",        "2 3 + .",                                    "5 ");
	check(&ctx, "user_word_square", ": square dup * ; 7 square .",                "49 ");
	check(&ctx, "conditional",      ": sign dup 0 < if drop 111 else 222 fi ; 5 sign .", "222 ");
	check(&ctx, "string_tell",      "s\" hello zforth\" tell",                    "hello zforth");
	check(&ctx, "fib_upstream_fixture",
	      ": fib 1 1 begin .. dup rot rot + dup 1e9 > until ; fib",
	      "1 2 3 5 8 13 21 34 55 89 144 233 377 610 987 1597 2584 4181 6765 10946 17711 28657 "
	      "46368 75025 121393 196418 317811 514229 832040 1346269 2178309 3524578 5702887 "
	      "9227465 14930352 24157816 39088168 63245984 102334152 165580128 267914272 433494400 "
	      "701408640 ");

	printf("KAT summary: %d run, %d failed\n", checks_run, checks_failed);
	return checks_failed == 0 ? 0 : 1;
}
