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
 * Native infinite loops are possible: a compiled zForth word using `begin ... again` (an
 * unconditional backward jmp) runs in run()'s `while(ctx->ip != 0)` C loop with no built-in
 * step budget -- there is no language-level interrupt to lean on at all here. So we arm an
 * INDEPENDENT interval timer (timer_create/CLOCK_MONOTONIC + a realtime signal) around each
 * zf_eval() call and longjmp out on expiry. Deliberately NOT alarm()/SIGALRM/ITIMER_REAL:
 * libFuzzer owns that timer for its own -timeout detection, and a harness that touches it either
 * gets silently swallowed or permanently disables libFuzzer's own timeout reporting.
 */

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

/* -------- independent watchdog: timer_create + a realtime signal, NOT SIGALRM -------- */

/* 1s per iteration (core.zf bootstrap + the fuzzed input). Measured headroom: upstream's own
 * forth/mandel.zf fixture (a legitimate, terminating nested-loop program) takes ~250-300ms under
 * ASan+UBSan instrumentation -- so 1s gives real bounded programs comfortable room while still
 * converting a genuine infinite `begin...again` loop into a fast, non-fatal return.
 * Split as whole-second + sub-second so it's never accidentally >= 1e9ns (itimerspec's tv_nsec
 * must be in [0, 999999999] -- a value of exactly 1000000000 makes timer_settime() fail EINVAL
 * and silently never arm at all, which was caught here empirically: an infinite-loop repro hung
 * forever instead of being bounded once this was miscoded as a bare nsec constant == 1e9). */
#define ZF_FUZZ_BUDGET_SEC 1
#define ZF_FUZZ_BUDGET_NSEC 0

static timer_t zf_fuzz_timer;
static int zf_fuzz_timer_ready = 0;
static sigjmp_buf zf_fuzz_jmp;

static void zf_fuzz_on_timeout(int sig, siginfo_t *si, void *uc)
{
	(void)sig;
	(void)si;
	(void)uc;
	siglongjmp(zf_fuzz_jmp, 1);
}

static void zf_fuzz_init_timer(void)
{
	struct sigaction sa;
	struct sigevent sev;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = zf_fuzz_on_timeout;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGRTMIN + 5, &sa, NULL);

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN + 5;
	timer_create(CLOCK_MONOTONIC, &sev, &zf_fuzz_timer);

	zf_fuzz_timer_ready = 1;
}

static void zf_fuzz_arm(void)
{
	struct itimerspec its;
	its.it_value.tv_sec = ZF_FUZZ_BUDGET_SEC;
	its.it_value.tv_nsec = ZF_FUZZ_BUDGET_NSEC;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	timer_settime(zf_fuzz_timer, 0, &its, NULL);
}

static void zf_fuzz_disarm(void)
{
	struct itimerspec its;
	memset(&its, 0, sizeof(its));
	timer_settime(zf_fuzz_timer, 0, &its, NULL);
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
	if (!zf_fuzz_timer_ready) {
		zf_fuzz_init_timer();
	}

	memcpy(buf, data, size);
	buf[size] = '\0';
	/* zf_eval() runs line-oriented via handle_char(); embedded NULs in the fuzzer input
	 * would just end the C string early via strchr-style scanning above -- harmless, just
	 * truncates this iteration's source text. */

	memset(&ctx, 0, sizeof(ctx));
	zf_init(&ctx, 0 /* trace off */);
	zf_bootstrap(&ctx);

	if (sigsetjmp(zf_fuzz_jmp, 1) == 0) {
		zf_fuzz_arm();
		/* Load the core vocabulary (defines `.`, `if`/`fi`, `begin`/`until`, `s"`,
		 * `variable`, `do`/`loop`, ...) so fuzzed input can reach far more of the
		 * interpreter than the dozen raw primitives alone. */
		zf_eval(&ctx, zf_core_src);
		zf_eval(&ctx, buf);
		zf_fuzz_disarm();
	} else {
		/* Watchdog fired: bound the native run() loop and move on to the next input
		 * instead of stalling the whole campaign. */
		zf_fuzz_disarm();
	}

	return 0;
}
