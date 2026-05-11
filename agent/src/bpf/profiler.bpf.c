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
} stack_events SEC(".maps");

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

/*
 * off_cpu_last_ts: rate-limits off-CPU stack captures to match the on-CPU
 * perf_event sampling frequency. Keyed by tgid (user-space PID), value is
 * ktime_get_ns() of the last capture for that PID.
 *
 * LRU_HASH: the kernel evicts the least-recently-used entry when the map
 * is full, so stale timestamps for PIDs that are no longer being monitored
 * are automatically reclaimed without any explicit cleanup path.
 * 4096 entries is safe headroom above the pid_filter_map ceiling of 1024.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} off_cpu_last_ts SEC(".maps");

/* 1 second in ns / 19 Hz ≈ 52 631 578 ns */
#define OFF_CPU_PERIOD_NS (1000000000ULL / 19)

/* off_cpu_period_ns is written from user-space (Rust) before the BPF
 * skeleton is loaded, using the same --freq value that drives perf_event.
 * This ensures both profilers share one sampling-frequency source of truth.
 *
 * The #define above is the kernel-side fallback — it is only used if the
 * rodata field is accidentally left at zero (which would mean no sampling
 * at all).  Under normal operation the Rust-side assignment overwrites it. */
volatile const __u64 off_cpu_period_ns;

/*
 * emit_stack_event — shared helper used by both on-CPU and off-CPU programs.
 *
 * Captures kernel and user stacks for the current task and submits a
 * stack_trace_event to the stack_events ring buffer.  Both callers hold
 * the same pid_filter_map check (map lookup, then call this helper), so
 * the logic is kept in one place to avoid drift.
 *
 * ctx  — BPF program context (perf_event or tracepoint — bpf_get_stack
 *         accepts both)
 * pid  — tgid of the task being sampled (caller already verified it is
 *         in pid_filter_map)
 * kind — STACK_KIND_ON_CPU or STACK_KIND_OFF_CPU
 */
static __always_inline void emit_stack_event(void *ctx, __u32 pid, __u8 kind)
{
    struct stack_trace_event *event = bpf_ringbuf_reserve(&stack_events, sizeof(*event), 0);
    if (!event) {
        struct error_event *err = bpf_ringbuf_reserve(&errors, sizeof(*err), 0);
        if (err) {
            err->kind = ERR_RESERVE_STACK_RINGBUF;
            err->timestamp_ns = bpf_ktime_get_ns();
            err->data.stack_reserve_err.pid = pid;
            bpf_ringbuf_submit(err, 0);
        }
        return;
    }

    event->pid  = pid;
    event->kind = kind;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->kernel_stack_sz = bpf_get_stack(ctx, event->kernel_stack, KERNEL_STACK_SIZE, 0);
    if (event->kernel_stack_sz < 0) {
        struct error_event *err = bpf_ringbuf_reserve(&errors, sizeof(*err), 0);
        if (err) {
            err->kind = ERR_STACK_FETCH;
            err->timestamp_ns = bpf_ktime_get_ns();
            err->data.stack_fetch_err.pid = pid;
            err->data.stack_fetch_err.ret_code = event->kernel_stack_sz;
            err->data.stack_fetch_err.space = SPACE_KERNEL;
            bpf_ringbuf_submit(err, 0);
        }
    }

    event->user_stack_sz = bpf_get_stack(ctx, event->user_stack, USER_STACK_SIZE,
                                          BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);
    if (event->user_stack_sz < 0) {
        struct error_event *err = bpf_ringbuf_reserve(&errors, sizeof(*err), 0);
        if (err) {
            err->kind = ERR_STACK_FETCH;
            err->timestamp_ns = bpf_ktime_get_ns();
            err->data.stack_fetch_err.pid = pid;
            err->data.stack_fetch_err.ret_code = event->user_stack_sz;
            err->data.stack_fetch_err.space = SPACE_USER;
            bpf_ringbuf_submit(err, 0);
        }
    }

    bpf_ringbuf_submit(event, 0);
}

SEC("perf_event")
int handle_perf(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32; // tgid in kernel terms = pid in user-space

    __u8 *active = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!active) {
        return 0;
    }

    emit_stack_event(ctx, pid, STACK_KIND_ON_CPU);
    return 0;
}

/*
 * handle_sched_switch — off-CPU profiler.
 *
 * Fires on every scheduler context switch.  The pid_filter_map lookup is
 * the first instruction: on a miss (99.9%+ of events) the program returns
 * in ~5 ns.  Only when a monitored PID transitions to TASK_UNINTERRUPTIBLE
 * (D state, blocked on IO or a kernel resource) do we capture the stack.
 *
 * We are still executing in prev's context when this tracepoint fires —
 * bpf_get_current_pid_tgid() returns prev's tgid and prev's page tables
 * are intact, so BPF_F_USER_STACK | BPF_F_USER_BUILD_ID is safe.
 *
 * TASK_UNINTERRUPTIBLE = 0x02.  This bit value has been stable since
 * Linux 2.6.  prev_state in the tracepoint is prev->__state masked to
 * the reportable bits — bit 1 set means the task is in D state.
 */
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    // Fast path: only capture D-state sleeps (blocked on IO / kernel resource).
    long prev_state = BPF_CORE_READ(ctx, prev_state);
    if (!(prev_state & 0x02)) // TASK_UNINTERRUPTIBLE
        return 0;

    // We are in prev's context: bpf_get_current_pid_tgid() returns prev's tgid.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u8 *active = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!active)
        return 0;

    // Rate-limit: emit at most one off-CPU sample per sampling period per PID,
    // matching the on-CPU perf_event cadence. off_cpu_period_ns is written
    // from user-space with the same --freq value that drives perf_event_open,
    // so both profilers share one frequency source of truth.
    __u64 period = off_cpu_period_ns ? off_cpu_period_ns : OFF_CPU_PERIOD_NS;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ts = bpf_map_lookup_elem(&off_cpu_last_ts, &pid);
    if (last_ts && (now - *last_ts) < period)
        return 0;
    bpf_map_update_elem(&off_cpu_last_ts, &pid, &now, BPF_ANY);

    emit_stack_event(ctx, pid, STACK_KIND_OFF_CPU);
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
            err->timestamp_ns = bpf_ktime_get_ns();
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
