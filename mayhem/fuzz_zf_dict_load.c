/*
 * mayhem/fuzz_zf_dict_load.c — libFuzzer harness for zForth's saved-dictionary LOAD path.
 *
 * zForth's own CLI supports `-l FILE`: src/linux/main.c's load() takes the raw pointer/length
 * from zf_dump() and fread()s a file DIRECTLY over the whole dictionary/uservar/stack memory
 * with zero validation:
 *
 *     void *p = zf_dump(ctx, &len);
 *     fread(p, 1, len, f);
 *
 * That is a distinct attack surface from zf_eval() on source text: it hands the interpreter's
 * word-lookup / dictionary-traversal logic (LATEST, HERE and the linked-list `next` pointers
 * baked into the dictionary bytes themselves) a fully attacker-controlled memory image. This
 * harness reproduces exactly that flow with fuzzer bytes standing in for the file content, then
 * exercises the loaded (possibly corrupt) dictionary with a couple of short, fixed Forth probes
 * that walk it (a bare numeric/word lookup, and `words` if it happens to resolve).
 *
 * No filesystem access: the "file" is the fuzzer's own input buffer.
 * Independent watchdog: same timer_create()-based scheme as fuzz_zf_eval.c (see there for why
 * not alarm()/SIGALRM).
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

/* 1s per probe, split as whole-second + sub-second (see fuzz_zf_eval.c: itimerspec's tv_nsec
 * must be < 1e9 or timer_settime() fails EINVAL and silently never arms). */
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
	sigaction(SIGRTMIN + 6, &sa, NULL); /* distinct rt signal from fuzz_zf_eval's +5 */

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN + 6;
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static zf_ctx ctx;
	size_t dump_len;
	void *dump;
	size_t n;

	if (size == 0) {
		return 0;
	}
	if (!zf_fuzz_timer_ready) {
		zf_fuzz_init_timer();
	}

	memset(&ctx, 0, sizeof(ctx));
	zf_init(&ctx, 0);

	/* Mirror main.c's load(): overwrite the raw dump region with attacker-controlled bytes,
	 * short input just leaves the tail as zf_init() left it (zero-filled ctx). */
	dump = zf_dump(&ctx, &dump_len);
	n = size < dump_len ? size : dump_len;
	memcpy(dump, data, n);

	if (sigsetjmp(zf_fuzz_jmp, 1) == 0) {
		zf_fuzz_arm();
		/* Exercise dictionary traversal (word lookup by name) and a couple of the
		 * lowest-level primitives against the now-untrusted dictionary state. */
		zf_eval(&ctx, "words\n");
		zf_eval(&ctx, "dup drop\n");
		zf_fuzz_disarm();
	} else {
		zf_fuzz_disarm();
	}

	return 0;
}
