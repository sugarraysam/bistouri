/*
 * mem-burner: memory-pressure workload for PSI integration tests.
 *
 * Generates sustained memory.pressure by repeatedly allocating anonymous
 * pages up to near the cgroup limit, then releasing them all and starting
 * over.  This forces the kernel into direct reclaim on every cycle,
 * generating memory.pressure stall time.
 *
 * Pressure generation mechanism:
 *   1. mmap() + memset() 56 × 1 MB chunks sequentially.
 *      Each memset triggers minor page faults that allocate physical pages.
 *      As the cgroup fills toward its 64 Mi limit, the kernel invokes
 *      direct reclaim — the process stalls (on-CPU, running kernel reclaim
 *      code) while the kernel scans LRU lists and evicts pages.
 *   2. munmap() all chunks — releases physical pages instantly.
 *   3. Repeat.
 *
 * Profiler visibility:
 *   memset() is genuine user-space CPU work (~250–500 µs per 1 MB chunk).
 *   The kernel's page fault handler and direct reclaim path also run
 *   on-CPU.  At 19 Hz perf_event sampling, each ~50–100 ms cycle contains
 *   at least one sample opportunity, yielding dozens of captured stacks
 *   over a 5-second capture window.
 *
 * OOM protection:
 *   Writes -1000 to /proc/self/oom_score_adj at startup.  Combined with
 *   a 56 MB arena (87.5% of the 64 Mi limit), there is a comfortable
 *   ~8 MB safety margin.
 *
 * Why not MADV_PAGEOUT?
 *   MADV_PAGEOUT is advisory and requires swap to evict anonymous pages.
 *   On Kubernetes nodes with swap disabled (the default), it is a no-op —
 *   pages stay resident and zero memory.pressure is generated.
 *
 * Helper functions are __attribute__((noinline)) to produce a multi-frame
 * stack trace, validating that the BPF frame-pointer unwinder can walk
 * beyond a single frame.
 */
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHUNK_SIZE (1024 * 1024)  /* 1 MB per chunk */
#define MAX_CHUNKS 56             /* 56 MB total — 87.5% of 64 Mi limit */

/*
 * Lower this process's OOM priority to -1000 (never kill).
 *
 * Safety: writes to /proc/self/oom_score_adj which is always writable by
 * the process itself. The write() return value is intentionally ignored —
 * failure is non-fatal; the 8 MB safety margin is the primary guard.
 */
static void oom_protect(void) {
    int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd >= 0) {
        const char *score = "-1000\n";
        write(fd, score, 6);
        close(fd);
    }
}

__attribute__((noinline)) static void touch_chunk(void *p, size_t size) {
    memset(p, 0xAA, size);
}

__attribute__((noinline)) static void *alloc_chunk(void) {
    void *p = mmap(NULL, CHUNK_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    touch_chunk(p, CHUNK_SIZE);
    return p;
}

__attribute__((noinline)) static void free_chunks(void **chunks, int n) {
    for (int i = 0; i < n; i++) {
        munmap(chunks[i], CHUNK_SIZE);
    }
}

int main(void) {
    oom_protect();

    void *chunks[MAX_CHUNKS];

    for (;;) {
        int n = 0;
        /* Allocate chunks until the limit or mmap failure. */
        for (; n < MAX_CHUNKS; n++) {
            void *p = alloc_chunk();
            if (!p)
                break;
            chunks[n] = p;
        }
        /* Release all at once — frees physical pages for the next cycle. */
        free_chunks(chunks, n);
    }

    return 0;
}
