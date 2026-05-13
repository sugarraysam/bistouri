/*
 * multi_dso.c — Second E2E fixture for multi-mapping sessions.
 *
 * Compiled separately from hello.c to produce a different build_id.
 * Used to test sessions where multiple mappings (build_ids) appear
 * in a single SessionPayload — validating per-mapping ELF fetch and
 * independent symbol resolution.
 */

__attribute__((noinline)) void compute_checksum(void) {
    volatile unsigned long crc = 0;
    for (volatile int i = 0; i < 100; i++) {
        crc ^= (unsigned long)i;
    }
    (void)crc;
}

__attribute__((noinline)) void process_packet(void) {
    compute_checksum();
}

int main(void) {
    process_packet();
    return 0;
}
