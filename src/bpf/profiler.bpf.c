// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "profiler.h"
#include <bpf/bpf_helpers.h>

SEC("perf_event")
int handle_perf(void *ctx)
{
    bpf_printk("hello world\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
