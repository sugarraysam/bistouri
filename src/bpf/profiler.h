// SPDX-License-Identifier: GPL-2.0

#ifndef __PROFILER_H
#define __PROFILER_H

#define TASK_COMM_LEN 16

struct event {
  u8 task[TASK_COMM_LEN];
  __u64 delta_us;
  pid_t pid;
};

#endif /* __PROFILER_H */
