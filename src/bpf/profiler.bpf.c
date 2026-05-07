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

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024); // Expected size: ~20KB (1024 entries * (20 bytes key + 4 bytes value))
    __type(key, struct comm_lpm_key);
    __type(value, __u32); // rule_id
    __uint(map_flags, BPF_F_NO_PREALLOC); // REQUIRED by Linux kernel for LPM_TRIE
} comm_lpm_trie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB for trigger events
} trigger_events SEC(".maps");

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
            err->data.stack_reserve_err.tgid = tgid;
            err->data.stack_reserve_err.pid = pid;
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
            err->data.stack_fetch_err.tgid = tgid;
            err->data.stack_fetch_err.pid = pid;
            err->data.stack_fetch_err.ret_code = event->kernel_stack_sz;
            err->data.stack_fetch_err.space = SPACE_KERNEL;
            bpf_ringbuf_submit(err, 0);
        }
    }

    event->user_stack_sz = bpf_get_stack(ctx, event->user_stack, MAX_STACK_SIZE, BPF_F_USER_STACK);
    if (event->user_stack_sz < 0) {
        struct error_event *err = bpf_ringbuf_reserve(&errors, sizeof(*err), 0);
        if (err) {
            err->kind = ERR_STACK_FETCH;
            err->data.stack_fetch_err.tgid = tgid;
            err->data.stack_fetch_err.pid = pid;
            err->data.stack_fetch_err.ret_code = event->user_stack_sz;
            err->data.stack_fetch_err.space = SPACE_USER;
            bpf_ringbuf_submit(err, 0);
        }
    }

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int match_comm_on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct comm_lpm_key key = {};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    // Prefix length for a full match is 16 bytes * 8 bits = 128
    key.prefixlen = sizeof(key.comm) * 8;

    __u32 *rule_id_ptr = bpf_map_lookup_elem(&comm_lpm_trie, &key);
    if (!rule_id_ptr) {
        return 0; // No rule match
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct process_match_event *event = bpf_ringbuf_reserve(&trigger_events, sizeof(*event), 0);
    if (!event) {
        struct error_event *err = bpf_ringbuf_reserve(&errors, sizeof(*err), 0);
        if (err) {
            err->kind = ERR_RESERVE_TRIGGER_RINGBUF;
            err->data.trigger_reserve_err.rule_id = *rule_id_ptr;
            err->data.trigger_reserve_err.pid = pid;
            bpf_ringbuf_submit(err, 0);
        }
        return 0;
    }

    event->rule_id = *rule_id_ptr;
    event->pid = pid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    
    __builtin_memcpy(event->comm, key.comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
