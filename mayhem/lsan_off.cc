// SPEC.md §6.2 item 15: disable LeakSanitizer preventively, at build time, for every
// ASan-instrumented binary — ASan/UBSan stay fully active, only leak detection is affected.
extern "C" int __lsan_is_turned_off() { return 1; }
