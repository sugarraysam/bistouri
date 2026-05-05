// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "profiler.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Up to 1024 concurrently monitored PIDs
    __type(key, __u32);
    __type(value, __u8);
} pid_filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024); // 64 MB
} perf_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024); // 64 KB
} errors SEC(".maps");

SEC("perf_event")
int handle_perf(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = pid_tgid & 0xFFFFFFFF;

    __u8 *active = bpf_map_lookup_elem(&pid_filter_map, &tgid);
    if (!active) {
        return 0;
    }

    struct bpf_perf_event *event = bpf_ringbuf_reserve(&perf_events, sizeof(*event), 0);
    if (!event) {
        struct error_event *err = bpf_ringbuf_reserve(&errors, sizeof(*err), 0);
        if (err) {
            err->kind = ERR_RESERVE_STACK_RINGBUF;
            err->data.reserve_err.tgid = tgid;
            err->data.reserve_err.pid = pid;
            bpf_ringbuf_submit(err, 0);
        }
        return 0;
    }

    event->tgid = tgid;
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->kernel_stack_sz = bpf_get_stack(ctx, event->kernel_stack, MAX_STACK_SIZE, 0);
    if (event->kernel_stack_sz < 0) {
        struct error_event *err = bpf_ringbuf_reserve(&errors, sizeof(*err), 0);
        if (err) {
            err->kind = ERR_STACK_FETCH;
            err->data.fetch_err.tgid = tgid;
            err->data.fetch_err.pid = pid;
            err->data.fetch_err.ret_code = event->kernel_stack_sz;
            err->data.fetch_err.space = SPACE_KERNEL;
            bpf_ringbuf_submit(err, 0);
        }
    }

    event->user_stack_sz = bpf_get_stack(ctx, event->user_stack, MAX_STACK_SIZE, BPF_F_USER_STACK);
    if (event->user_stack_sz < 0) {
        struct error_event *err = bpf_ringbuf_reserve(&errors, sizeof(*err), 0);
        if (err) {
            err->kind = ERR_STACK_FETCH;
            err->data.fetch_err.tgid = tgid;
            err->data.fetch_err.pid = pid;
            err->data.fetch_err.ret_code = event->user_stack_sz;
            err->data.fetch_err.space = SPACE_USER;
            bpf_ringbuf_submit(err, 0);
        }
    }

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
