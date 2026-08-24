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
 * The harness arms no timer. zf_eval()'s word lookup (find_word) follows the dictionary's `next`
 * links with no bound, so a loaded image whose chain cycles never terminates -- and that is
 * trivially reachable (a word whose link points at itself), so it would stall every exec of the
 * campaign instead of being a one-off finding. Instead of a wall-clock guard, the harness
 * rejects such an image up front (-1) with a deterministic check: a valid dictionary only links
 * strictly backwards, so any link that does not is not a dictionary. Everything else
 * (out-of-range links, junk words) still reaches upstream, which aborts on it cleanly.
 * Bytecode a loaded word runs is bounded the same way, by a step budget (zf_host_trace below).
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

/*
 * Mirrors the walk find_word() does over the link chain from LATEST, using the cell encoding of
 * dict_get_cell: 1 byte if < 0x80, 2 bytes, or 0xff followed by a raw zf_cell. If upstream
 * changes that cell encoding, this walk has to be updated to match.
 *
 * Returns 0 if the chain does not strictly descend, if a link is a raw float, or if a link points
 * into the user variables (a real dictionary never does either). Returns 1 for an unreadable cell:
 * upstream aborts there, so there is nothing to guard.
 */
static int zf_fuzz_chain_descends(const uint8_t *dict)
{
	zf_addr w;
	memcpy(&w, dict + ZF_USERVAR_LATEST * sizeof(zf_addr), sizeof(w));

	while (w) {
		if (w < ZF_USERVAR_COUNT * sizeof(zf_addr)) {
			return 0; /* words start after the user variables, which sit at the dict's base */
		}
		size_t p = w;
		unsigned link;

		if (p >= ZF_DICT_SIZE - 2) {
			return 1;
		}
		p += dict[p] == 0xff ? 1 + sizeof(zf_cell) : (dict[p] & 0x80) ? 2 : 1;

		if (p >= ZF_DICT_SIZE - 2) {
			return 1;
		}
		if (dict[p] == 0xff) {
			return 0; /* a raw-float link is never what a real dictionary encodes */
		}
		link = (dict[p] & 0x80) ? ((dict[p] & 0x3fu) << 8) + dict[p + 1] : dict[p];

		if (link >= w) {
			return 0;
		}
		w = link;
	}
	return 1;
}

/* Deterministic step budget. run() calls this once per executed op while the `trace` user
 * variable is set, so counting the calls bounds how much bytecode a corrupt dictionary can run
 * (a word whose code jumps to itself never returns otherwise). The chain is re-checked on every
 * call too, because the bytecode can rewrite the dictionary after the load-time check. Over
 * budget, or on a broken chain, zf_abort() takes zForth's own error path -- zf_eval() returns
 * normally. No clock is involved. */
#define ZF_FUZZ_MAX_TRACE_CALLS 2000

static unsigned zf_fuzz_trace_calls;

void zf_host_trace(zf_ctx *ctx, const char *fmt, va_list va)
{
	(void)fmt;
	(void)va;
	if (++zf_fuzz_trace_calls > ZF_FUZZ_MAX_TRACE_CALLS || !zf_fuzz_chain_descends(ctx->dict)) {
		zf_abort(ctx, ZF_ABORT_EXTERNAL);
	}
}

/* One word per eval, so the chain is re-checked before every lookup. */
static int zf_fuzz_eval(zf_ctx *ctx, const char *word)
{
	zf_fuzz_trace_calls = 0;
	zf_uservar_set(ctx, ZF_USERVAR_TRACE, 1); /* lives in the dict: set it before checking */
	if (!zf_fuzz_chain_descends(ctx->dict)) {
		return -1;
	}
	zf_eval(ctx, word);
	return 0;
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static zf_ctx ctx;
	size_t dump_len;
	void *dump;
	size_t n;

	if (size == 0) {
		return 0;
	}

	memset(&ctx, 0, sizeof(ctx));
	zf_init(&ctx, 0);

	/* Mirror main.c's load(): overwrite the raw dump region with attacker-controlled bytes,
	 * short input just leaves the tail as zf_init() left it (zero-filled ctx). */
	dump = zf_dump(&ctx, &dump_len);
	n = size < dump_len ? size : dump_len;
	memcpy(dump, data, n);

	/* Exercise dictionary traversal (word lookup by name) and a couple of the
	 * lowest-level primitives against the now-untrusted dictionary state. */
	if (zf_fuzz_eval(&ctx, "words\n") || zf_fuzz_eval(&ctx, "dup\n") ||
	    zf_fuzz_eval(&ctx, "drop\n")) {
		return -1;
	}

	return 0;
}
