/*
 * io-burner: IO-bound workload for PSI integration tests.
 *
 * Generates io.pressure by writing sequential dirty pages to disk with
 * fdatasync(). The off-CPU BPF profiler (handle_sched_switch) captures
 * the stack at the moment fdatasync() blocks the process in
 * TASK_UNINTERRUPTIBLE state, providing genuine IO-wait stack traces.
 *
 * No artificial CPU spin is needed: the sched_switch tracepoint fires
 * precisely when the process enters D state, so the captured kernel
 * stack will show the fdatasync → writeback → block-layer call chain.
 *
 * IO pressure mechanism:
 *   write() to page cache (fast, no stall) then fdatasync() to flush
 *   dirty pages to the block device. Under the cgroupv2 io.max
 *   throttle (16 MB/s) a 1 MB burst takes ~62 ms to flush, stalling
 *   the process and reliably triggering io.pressure.
 *
 * Helper functions are __attribute__((noinline)) to produce a multi-frame
 * stack trace, validating that the BPF frame-pointer unwinder can walk
 * beyond a single frame.
 */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define PAGE_SIZE       4096
#define PAGES_PER_BURST 256   /* 1 MB per burst */

static char buf[PAGE_SIZE];

__attribute__((noinline)) static void write_page(int fd) {
    write(fd, buf, PAGE_SIZE);
}

__attribute__((noinline)) static void write_burst(int fd) {
    for (int i = 0; i < PAGES_PER_BURST; i++) {
        write_page(fd);
    }
    /* Flush dirty pages to block device — this is where the process
     * enters TASK_UNINTERRUPTIBLE, generating io.pressure and triggering
     * the off-CPU BPF profiler to capture the stack. */
    fdatasync(fd);
}

int main(void) {
    int fd = open("/tmp/io_burn", O_WRONLY | O_CREAT, 0644);
    if (fd < 0)
        return 1;

    memset(buf, 'A', PAGE_SIZE);

    for (;;) {
        lseek(fd, 0, SEEK_SET);
        write_burst(fd);
        /* Release dirty pages so the next burst writes fresh ones. */
        ftruncate(fd, 0);
    }

    return 0;
}
