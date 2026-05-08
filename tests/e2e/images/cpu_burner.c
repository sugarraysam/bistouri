/*
 * cpu-burner: lightweight CPU-bound workload for PSI integration tests.
 *
 * The program itself is intentionally simple — PSI cpu pressure comes from
 * the tight Kubernetes CPU limit (100m), not from workload intensity.
 * The cgroup CPU throttler stalls the task, which the kernel records as
 * cpu.pressure.
 */
#include <math.h>

int main(void) {
    volatile double x = 1.0;
    for (;;) {
        x = sqrt(x + 1.0);
    }
    return 0;
}
