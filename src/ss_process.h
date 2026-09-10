/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_PROCESS_H
#define SS_PROCESS_H
#include <stdbool.h>
#include <stdint.h>
struct ss_process;
struct ss_process *ss_process_new(const char *program);
void ss_process_arg(struct ss_process *process, const char *argument);
void ss_process_env(struct ss_process *process, const char *name, const char *value);
int ss_process_start(struct ss_process *process, uint16_t control_port);
bool ss_process_running(struct ss_process *process);
void ss_process_free(struct ss_process *process);
#endif
