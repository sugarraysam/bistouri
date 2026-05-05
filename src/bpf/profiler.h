// SPDX-License-Identifier: GPL-2.0

#ifndef __PROFILER_H
#define __PROFILER_H

#define MAX_STACK_DEPTH 127
#define TASK_COMM_LEN 16

#define MAX_STACK_SIZE (MAX_STACK_DEPTH * 8)

struct bpf_perf_event {
    __u32 tgid;
    __u32 pid;
    __u8 comm[TASK_COMM_LEN];
    __s32 kernel_stack_sz;
    __s32 user_stack_sz;
    __u64 kernel_stack[MAX_STACK_DEPTH];
    __u64 user_stack[MAX_STACK_DEPTH];
};

enum error_kind {
    ERR_RESERVE_STACK_RINGBUF = 1,
    ERR_STACK_FETCH = 2,
};

enum space_kind {
    SPACE_KERNEL = 0,
    SPACE_USER = 1,
};

struct err_reserve_stack_ringbuf {
    __u32 tgid;
    __u32 pid;
};

struct err_stack_fetch {
    __u32 tgid;
    __u32 pid;
    __s32 ret_code;
    __u32 space;
};

struct error_event {
    __u32 kind;
    union {
        struct err_reserve_stack_ringbuf reserve_err;
        struct err_stack_fetch fetch_err;
    } data;
};

#endif /* __PROFILER_H */
