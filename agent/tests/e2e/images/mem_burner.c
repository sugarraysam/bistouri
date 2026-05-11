/*
 * mem-burner: memory-pressure workload for PSI integration tests.
 *
 * Generates sustained memory.pressure without triggering the OOM killer by
 * keeping total allocation well below the cgroup limit. With a 64Mi cgroup
 * limit, we allocate 40 MB and continuously force page reclaim by discarding
 * and re-faulting the same physical pages with MADV_PAGEOUT + sequential
 * memset.
 *
 * OOM protection:
 *   Writes -1000 to /proc/self/oom_score_adj at startup. This marks the
 *   process as the lowest-priority OOM victim, so the kernel will never
 *   choose it for termination even if memory pressure peaks unexpectedly.
 *   Combined with a 40 MB arena (62% of the 64 Mi limit), there is a
 *   comfortable 24 MB safety margin.
 *
 * Pressure generation mechanism:
 *   1. mmap() a 40 MB arena (MAP_PRIVATE | MAP_ANONYMOUS).
 *   2. Touch all pages sequentially (memset) to fault them in.
 *   3. madvise(MADV_PAGEOUT) to ask the kernel to reclaim those pages.
 *   4. Re-touch all pages — forces hard page faults, stalling the process
 *      while the kernel refaults the pages back in.
 *   5. Repeat indefinitely.
 *
 * This stall pattern is what generates memory.pressure (the kernel records
 * time the cgroup is stalled waiting for memory). The process stays on-CPU
 * during the memset phase, making it visible to the perf_event profiler.
 *
 * Helper functions are __attribute__((noinline)) to produce a multi-frame
 * stack trace, validating that the BPF frame-pointer unwinder can walk
 * beyond a single frame.
 */
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ARENA_SIZE (40 * 1024 * 1024)  /* 40 MB — 62% of 64 Mi limit */
#define CHUNK      (4 * 1024)           /* 4 KB = one page */

/*
 * Lower this process's OOM priority to -1000 (never kill).
 *
 * Safety: writes to /proc/self/oom_score_adj which is always writable by
 * the process itself. The write() return value is intentionally ignored —
 * failure is non-fatal; the 24 MB safety margin is the primary guard.
 */
static void oom_protect(void) {
    int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd >= 0) {
        const char *score = "-1000\n";
        write(fd, score, 6);
        close(fd);
    }
}

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
    oom_protect();

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
