// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * (C) COPYRIGHT 2023 ARM Limited. All rights reserved.
 */

/* Create the tracepoint when the kernel does not provide it. */
#ifndef CONFIG_TRACE_POWER_GPU_WORK_PERIOD
#if IS_ENABLED(CONFIG_MALI_TRACE_POWER_GPU_WORK_PERIOD)
#define CREATE_TRACE_POINTS
#include "mali_power_gpu_work_period_trace.h"
#endif
#endif
