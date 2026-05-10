/*
 * mem-hog: memory-bound workload for PSI integration tests.
 *
 * Allocates anonymous memory pages via mmap until near the cgroup limit,
 * holds them all simultaneously, then releases them and repeats. This
 * forces the kernel into page reclaim on every cycle, generating
 * memory.pressure.
 *
 * With a 64Mi cgroup limit, allocating ~56 MB in 1 MB chunks creates
 * sustained memory pressure without triggering the OOM killer.
 */
#include <string.h>
#include <sys/mman.h>

#define CHUNK_SIZE (1024 * 1024)  /* 1 MB per chunk */
#define MAX_CHUNKS 56             /* ~56 MB total, within 64Mi limit */

int main(void) {
    void *chunks[MAX_CHUNKS];

    for (;;) {
        int n = 0;
        /* Allocate chunks until limit or failure. */
        for (; n < MAX_CHUNKS; n++) {
            void *p = mmap(NULL, CHUNK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
            if (p == MAP_FAILED)
                break;
            /* Touch every page to force physical allocation. */
            memset(p, 0xAA, CHUNK_SIZE);
            chunks[n] = p;
        }
        /* Release all at once — forces kernel page reclaim. */
        for (int i = 0; i < n; i++) {
            munmap(chunks[i], CHUNK_SIZE);
        }
    }
    return 0;
}
