/*
 * io-burner: lightweight IO-bound workload for PSI integration tests.
 *
 * Writes a 4KB buffer then calls fsync() in a tight loop. The synchronous
 * fsync forces the process to wait for the block device, which the kernel
 * records as io.pressure. No Kubernetes IO limits needed — the fsync
 * pattern creates natural IO wait on any filesystem.
 */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char buf[4096];
    memset(buf, 'A', sizeof(buf));

    int fd = open("/tmp/io_burn", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return 1;

    for (;;) {
        lseek(fd, 0, SEEK_SET);
        write(fd, buf, sizeof(buf));
        fsync(fd);
    }

    return 0;
}
