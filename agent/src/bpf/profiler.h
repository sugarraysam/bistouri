// SPDX-License-Identifier: GPL-2.0

#ifndef __PROFILER_H
#define __PROFILER_H

#define MAX_STACK_DEPTH 127
#define TASK_COMM_LEN 16
#define BUILD_ID_SIZE 20

#define KERNEL_STACK_SIZE (MAX_STACK_DEPTH * 8)
#define USER_STACK_SIZE   (MAX_STACK_DEPTH * sizeof(struct user_stack_frame))

// Mirrors kernel's struct bpf_stack_build_id layout exactly.
// bpf_get_stack() with BPF_F_USER_BUILD_ID writes these into the buffer.
//
// status values:
//   0 = empty (end of trace)
//   1 = valid (build_id + file_offset resolved)
//   2 = fallback_ip (kernel couldn't resolve build_id — JIT, vDSO, etc.)
struct user_stack_frame {
    __s32 status;
    unsigned char build_id[BUILD_ID_SIZE];
    union {
        __u64 offset;  // file offset when status=1
        __u64 ip;      // raw instruction pointer when status=2
    };
};

struct stack_trace_event {
    __u32 pid;
    __u8 comm[TASK_COMM_LEN];
    __s32 kernel_stack_sz;
    __s32 user_stack_sz;
    __u64 kernel_stack[MAX_STACK_DEPTH];
    struct user_stack_frame user_stack[MAX_STACK_DEPTH];
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
    __u32 _pad;             // explicit padding for u64 alignment
    __u64 timestamp_ns;     // bpf_ktime_get_ns() — nanoseconds since boot
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
