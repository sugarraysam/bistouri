/*
 * hello.c — E2E fixture for symbolizer testing.
 *
 * Multi-frame call chain with known symbols. Compiled with:
 *   gcc -g -O0 -static -fno-omit-frame-pointer -Wl,--build-id -o hello hello.c
 *
 * Functions are __attribute__((noinline)) to guarantee distinct frames
 * in the symbol table. The symbolizer resolves file_offsets back to
 * these exact function names, source files, and line numbers.
 */

__attribute__((noinline)) void target_function(void) {
    volatile int x = 42;
    (void)x;
}

__attribute__((noinline)) void outer_call(void) {
    target_function();
}

int main(void) {
    outer_call();
    return 0;
}
