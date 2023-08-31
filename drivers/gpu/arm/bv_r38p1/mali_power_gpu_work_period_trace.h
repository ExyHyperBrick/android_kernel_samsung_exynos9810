/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * (C) COPYRIGHT 2023 ARM Limited. All rights reserved.
 */

#ifndef _TRACE_POWER_GPU_WORK_PERIOD_MALI
#define _TRACE_POWER_GPU_WORK_PERIOD_MALI
#endif

#undef TRACE_SYSTEM
#define TRACE_SYSTEM power
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mali_power_gpu_work_period_trace
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#if !defined(_TRACE_POWER_GPU_WORK_PERIOD_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_POWER_GPU_WORK_PERIOD_H

#include <linux/tracepoint.h>

/**
 * gpu_work_period - Report per-application GPU work metrics
 * @gpu_id: Unique GPU identifier
 * @uid: Android application UID
 * @start_time_ns: Start of the work period in CLOCK_MONOTONIC_RAW ns
 * @end_time_ns: End of the work period in CLOCK_MONOTONIC_RAW ns
 * @total_active_duration_ns: Non-overlapping active time for this UID
 */
TRACE_EVENT(gpu_work_period,

	TP_PROTO(u32 gpu_id, u32 uid, u64 start_time_ns, u64 end_time_ns,
		 u64 total_active_duration_ns),

	TP_ARGS(gpu_id, uid, start_time_ns, end_time_ns,
		total_active_duration_ns),

	TP_STRUCT__entry(
		__field(u32, gpu_id)
		__field(u32, uid)
		__field(u64, start_time_ns)
		__field(u64, end_time_ns)
		__field(u64, total_active_duration_ns)
	),

	TP_fast_assign(
		__entry->gpu_id = gpu_id;
		__entry->uid = uid;
		__entry->start_time_ns = start_time_ns;
		__entry->end_time_ns = end_time_ns;
		__entry->total_active_duration_ns = total_active_duration_ns;
	),

	TP_printk("gpu_id=%u uid=%u start_time_ns=%llu end_time_ns=%llu total_active_duration_ns=%llu",
		  __entry->gpu_id, __entry->uid, __entry->start_time_ns,
		  __entry->end_time_ns, __entry->total_active_duration_ns)
);

#endif /* _TRACE_POWER_GPU_WORK_PERIOD_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
