// SPDX-License-Identifier: GPL-2.0

#ifndef __PROFILER_H
#define __PROFILER_H

#define MAX_STACK_DEPTH 127
#define TASK_COMM_LEN 16

#define MAX_STACK_SIZE (MAX_STACK_DEPTH * 8)

struct stack_trace_event {
    __u32 pid;
    __u8 comm[TASK_COMM_LEN];
    __s32 kernel_stack_sz;
    __s32 user_stack_sz;
    __u64 kernel_stack[MAX_STACK_DEPTH];
    __u64 user_stack[MAX_STACK_DEPTH];
};

enum error_kind {
    ERR_RESERVE_STACK_RINGBUF   = 1,
    ERR_STACK_FETCH             = 2,
    ERR_RESERVE_TRIGGER_RINGBUF = 3,
};

enum space_kind {
    SPACE_KERNEL = 0,
    SPACE_USER = 1,
};

struct err_reserve_stack_ringbuf {
    __u32 pid;
};

struct err_stack_fetch {
    __u32 pid;
    __s32 ret_code;
    __u32 space;
};

struct err_reserve_trigger_ringbuf {
    __u32 rule_id;
    __u32 pid;
};

struct error_event {
    __u32 kind;
    union {
        struct err_reserve_stack_ringbuf stack_reserve_err;
        struct err_stack_fetch stack_fetch_err;
        struct err_reserve_trigger_ringbuf trigger_reserve_err;
    } data;
};

struct comm_lpm_key {
    __u32 prefixlen; // in bits
    char comm[TASK_COMM_LEN];
};

struct process_match_event {
    __u32 rule_id;
    __u32 pid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
};

#endif /* __PROFILER_H */
