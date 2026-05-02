// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "profiler.h"
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    bpf_printk("Hello from BPF!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
