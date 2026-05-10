/*
 * mem-burner: memory-pressure workload for PSI integration tests.
 *
 * Generates sustained memory.pressure without triggering the OOM killer by
 * keeping total allocation well below the cgroup limit. With a 64Mi cgroup
 * limit, we allocate 48 MB and continuously force page reclaim by discarding
 * and re-faulting the same physical pages with MADV_PAGEOUT + MAP_POPULATE.
 *
 * Pressure generation mechanism:
 *   1. mmap() a 48 MB arena (MAP_PRIVATE | MAP_ANONYMOUS).
 *   2. Touch all pages (MAP_POPULATE alternative via memset) to fault them in.
 *   3. madvise(MADV_PAGEOUT) to ask the kernel to reclaim those pages.
 *   4. Re-touch all pages — forces hard page faults, stalling the process
 *      while the kernel refaults the pages back in.
 *   5. Repeat indefinitely.
 *
 * This stall pattern is what generates memory.pressure (the kernel records
 * time the cgroup is stalled waiting for memory). Unlike the original
 * approach, we never approach the OOM limit — 48/64 MB = 75% utilization
 * leaves a 16 MB safety margin.
 *
 * Helper functions are __attribute__((noinline)) to produce a multi-frame
 * stack trace, validating that the BPF frame-pointer unwinder can walk
 * beyond a single frame.
 */
#include <string.h>
#include <sys/mman.h>

#define ARENA_SIZE (48 * 1024 * 1024)  /* 48 MB — safely under 64Mi limit */
#define CHUNK      (4 * 1024)           /* 4 KB = one page */

__attribute__((noinline)) static void evict_pages(void *p, size_t size) {
    madvise(p, size, MADV_PAGEOUT);
}

__attribute__((noinline)) static void fault_pages(void *p, size_t size) {
    /* Touch every page to force hard page faults after eviction. */
    volatile char *ptr = (volatile char *)p;
    for (size_t i = 0; i < size; i += CHUNK) {
        ptr[i] = (char)i;
    }
}

int main(void) {
    void *arena = mmap(NULL, ARENA_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED)
        return 1;

    /* Initial population: fault all pages in once. */
    fault_pages(arena, ARENA_SIZE);

    for (;;) {
        /* Ask the kernel to reclaim our pages → process stalls on refault. */
        evict_pages(arena, ARENA_SIZE);

        /* Re-touch all pages: generates hard page faults → memory.pressure. */
        fault_pages(arena, ARENA_SIZE);
    }

    return 0;
}
