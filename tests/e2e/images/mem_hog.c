/*
 * mem-hog: lightweight memory-bound workload for PSI integration tests.
 *
 * Allocates a 16 MB chunk, touches every page (forces physical allocation),
 * then frees it — in a loop. With a tight Kubernetes memory limit (32Mi),
 * the kernel aggressively reclaims pages, which it records as
 * memory.pressure.
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    const size_t chunk = 16 * 1024 * 1024; /* 16 MB */
    for (;;) {
        char *p = malloc(chunk);
        if (!p)
            continue;
        memset(p, 0xAA, chunk);
        free(p);
    }
    return 0;
}
