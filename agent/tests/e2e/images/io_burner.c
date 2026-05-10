/*
 * io-burner: IO-bound workload for PSI integration tests.
 *
 * Creates IO pressure by writing large buffers with O_SYNC in a tight
 * loop. The key to generating measurable io.pressure in containerized
 * environments (Kind, overlay filesystems) is volume: write enough data
 * per iteration that the kernel must flush to the backing device.
 *
 * Writes 1 MB per iteration (256 × 4KB pages) with O_SYNC, then drops
 * the page cache to prevent the kernel from coalescing writes.
 *
 * Helper functions are __attribute__((noinline)) to produce a multi-frame
 * stack trace, validating that the BPF frame-pointer unwinder can walk
 * beyond a single frame.
 */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* 4 KB aligned buffer — matches page size for efficient flushing. */
static char buf[4096];

__attribute__((noinline)) static void write_page(int fd) {
    lseek(fd, 0, SEEK_SET);
    write(fd, buf, sizeof(buf));
}

__attribute__((noinline)) static void write_burst(int fd) {
    /* Write 1 MB per burst — 256 sync writes per loop. */
    for (int i = 0; i < 256; i++) {
        write_page(fd);
    }
}

int main(void) {
    memset(buf, 'A', sizeof(buf));

    int fd = open("/tmp/io_burn", O_WRONLY | O_CREAT | O_SYNC, 0644);
    if (fd < 0)
        return 1;

    for (;;) {
        write_burst(fd);
        /* Force data + metadata to disk. */
        fdatasync(fd);
        /* Advise kernel to drop page cache — creates IO on next write. */
        posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    }

    return 0;
}
