/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * (C) COPYRIGHT 2023 ARM Limited. All rights reserved.
 */

/**
 * DOC: GPU metrics frontend APIs
 */

#ifndef _KBASE_GPU_METRICS_H_
#define _KBASE_GPU_METRICS_H_

#if IS_ENABLED(CONFIG_MALI_TRACE_POWER_GPU_WORK_PERIOD)
#include <mali_kbase.h>

/**
 * kbase_gpu_metrics_get_emit_interval() - Return the tracepoint interval
 *
 * Return: Emission interval in nanoseconds.
 */
unsigned long kbase_gpu_metrics_get_emit_interval(void);

void kbase_gpu_metrics_ctx_put(struct kbase_device *kbdev,
			       struct kbase_gpu_metrics_ctx *gpu_metrics_ctx);

/**
 * kbase_gpu_metrics_ctx_get() - Find and reference an application's state
 * @kbdev: GPU device
 * @aid: Android application UID
 *
 * Return: Existing application state, or NULL.
 */
struct kbase_gpu_metrics_ctx *
kbase_gpu_metrics_ctx_get(struct kbase_device *kbdev, u32 aid);

void kbase_gpu_metrics_ctx_init(struct kbase_device *kbdev,
				struct kbase_gpu_metrics_ctx *gpu_metrics_ctx,
				u32 aid);

/**
 * kbase_gpu_metrics_ctx_start_activity() - Record application GPU start
 * @kctx: Kbase context contributing activity
 * @timestamp_ns: CLOCK_MONOTONIC_RAW timestamp
 */
void kbase_gpu_metrics_ctx_start_activity(struct kbase_context *kctx,
					  u64 timestamp_ns);

/**
 * kbase_gpu_metrics_ctx_end_activity() - Record application GPU completion
 * @kctx: Kbase context contributing activity
 * @timestamp_ns: CLOCK_MONOTONIC_RAW timestamp
 */
void kbase_gpu_metrics_ctx_end_activity(struct kbase_context *kctx,
					u64 timestamp_ns);

/**
 * kbase_gpu_metrics_emit_tracepoint() - Emit active application periods
 * @kbdev: GPU device
 * @timestamp_ns: CLOCK_MONOTONIC_RAW emission timestamp
 */
void kbase_gpu_metrics_emit_tracepoint(struct kbase_device *kbdev,
				       u64 timestamp_ns);

/**
 * kbase_gpu_metrics_init() - Initialize per-device metrics state
 * @kbdev: GPU device
 *
 * Return: 0.
 */
int kbase_gpu_metrics_init(struct kbase_device *kbdev);

/**
 * kbase_gpu_metrics_term() - Validate and terminate metrics state
 * @kbdev: GPU device
 */
void kbase_gpu_metrics_term(struct kbase_device *kbdev);

#endif
#endif /* _KBASE_GPU_METRICS_H_ */
