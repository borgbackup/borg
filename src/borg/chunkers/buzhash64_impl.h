/* buzhash64 chunker scan kernel: the cyclic-polynomial rolling hash inner
 * loop, with blockwise/SIMD implementations that are bit-identical to the
 * plain sequential loop (see buzhash64_impl.c for the algebra).
 *
 * The cut decision granularity stays at 1 byte: every position is tested
 * against the mask, exactly as in the sequential loop. */

#ifndef BORG_BUZHASH64_IMPL_H
#define BORG_BUZHASH64_IMPL_H

#include <stdint.h>
#include <stddef.h>

/* Scan up to n positions with the buzhash64 test-then-update loop:
 *   j = 0
 *   while j < n and (sum & mask) != 0:
 *       sum = ROTL1(sum) ^ table_rot[p_rem[j]] ^ table[p_add[j]];  j += 1
 * Returns j (the number of update steps performed); sum is left at the exit
 * state, i.e. either (sum & mask) == 0 or j == n.
 * table: the keyed 256-entry table; table_rot[b] must be
 * ROTL(table[b], window_size % 64) (precomputed by the caller).
 * p_rem points at the byte leaving the window, p_add at the byte entering
 * (p_add = p_rem + window_size); both must have n readable bytes.
 * kernel is one of BZ_K_*; BZ_K_AUTO picks the best one this CPU can run.
 * All kernels return bit-identical results. */
/* Scan kernel ids, a tier ladder; see fastcdc_impl.h for the rationale. */
#define BZ_K_AUTO 0      /* best kernel this CPU can run */
#define BZ_K_SCALAR 1    /* sequential reference loop */
#define BZ_K_BLOCKWISE 2 /* portable 8-lane C */
#define BZ_K_VECTOR 3    /* avx2 (there is no aarch64 vector kernel) */
#define BZ_K_VECTOR512 4 /* avx512 */

/* Results of bz64_kernel_select(). */
#define BZ_KSEL_OK 0
#define BZ_KSEL_UNKNOWN 1  /* not a kernel name on this platform */
#define BZ_KSEL_NOTBUILT 2 /* known, but not compiled into this binary */
#define BZ_KSEL_NOCPU 3    /* known and built, but this CPU cannot run it */

/* Resolve a kernel name for this build; see fc_kernel_select(). */
int bz64_kernel_select(const char *name, int *out_id);

/* Comma-separated list of the kernel names this build accepts. */
const char *bz64_kernel_names(void);

size_t bz64_scan(const uint64_t *table, const uint64_t *table_rot,
                 const uint8_t *p_rem, const uint8_t *p_add,
                 size_t n, uint64_t *sum, uint64_t mask, int kernel);

/* Name of the kernel <kernel> selects: "avx512", "avx2", "blockwise" or
 * "scalar" (there is no vector kernel on aarch64, see buzhash64_impl.c).
 * For BZ_K_AUTO, the auto-selected one. */
const char *bz64_kernel_name(int kernel);

#endif
