#ifndef _ASM_X86_CACHEFLUSH_H
#define _ASM_X86_CACHEFLUSH_H

/* Caches aren't brain-dead on the intel. */
#include <asm-generic/cacheflush.h>
#include <asm/special_insns.h>
#include <asm/set_memory.h>

void clflush_cache_range(void *addr, unsigned int size);

#define mmio_flush_range(addr, size) clflush_cache_range(addr, size)

extern const int rodata_test_data;

#ifdef CONFIG_DEBUG_RODATA_TEST
int rodata_test(void);
#else
static inline int rodata_test(void)
{
	return 0;
}
#endif

#endif /* _ASM_X86_CACHEFLUSH_H */
