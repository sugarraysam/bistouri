/*
 * cpu-burner: lightweight CPU-bound workload for PSI integration tests.
 *
 * The program itself is intentionally simple — PSI cpu pressure comes from
 * the tight Kubernetes CPU limit (100m), not from workload intensity.
 * The cgroup CPU throttler stalls the task, which the kernel records as
 * cpu.pressure.
 *
 * Helper functions are __attribute__((noinline)) to produce a multi-frame
 * stack trace, validating that the BPF frame-pointer unwinder can walk
 * beyond a single frame.
 */
#include <math.h>

__attribute__((noinline)) static double inner_burn(double x) {
    return sqrt(x + 1.0);
}

__attribute__((noinline)) static double outer_burn(double x) {
    return inner_burn(x);
}

int main(void) {
    volatile double x = 1.0;
    for (;;) {
        x = outer_burn(x);
    }
    return 0;
}
