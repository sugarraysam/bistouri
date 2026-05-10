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
 *
 * Helper functions are __attribute__((noinline)) to produce a multi-frame
 * stack trace, validating that the BPF frame-pointer unwinder can walk
 * beyond a single frame.
 */
#include <string.h>
#include <sys/mman.h>

#define CHUNK_SIZE (1024 * 1024)  /* 1 MB per chunk */
#define MAX_CHUNKS 56             /* ~56 MB total, within 64Mi limit */

__attribute__((noinline)) static void touch_chunk(void *p, size_t size) {
    memset(p, 0xAA, size);
}

__attribute__((noinline)) static void *alloc_chunk(void) {
    void *p = mmap(NULL, CHUNK_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    touch_chunk(p, CHUNK_SIZE);
    return p;
}

int main(void) {
    void *chunks[MAX_CHUNKS];

    for (;;) {
        int n = 0;
        /* Allocate chunks until limit or failure. */
        for (; n < MAX_CHUNKS; n++) {
            void *p = alloc_chunk();
            if (!p)
                break;
            chunks[n] = p;
        }
        /* Release all at once — forces kernel page reclaim. */
        for (int i = 0; i < n; i++) {
            munmap(chunks[i], CHUNK_SIZE);
        }
    }
    return 0;
}
