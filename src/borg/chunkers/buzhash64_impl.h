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
 * force_scalar != 0 selects the sequential reference loop (for tests);
 * all kernels return bit-identical results. */
size_t bz64_scan(const uint64_t *table, const uint64_t *table_rot,
                 const uint8_t *p_rem, const uint8_t *p_add,
                 size_t n, uint64_t *sum, uint64_t mask, int force_scalar);

/* Name of the kernel bz64_scan would use: "avx512", "avx2", "blockwise" or "scalar"
 * (there is no vector kernel on aarch64, see buzhash64_impl.c). */
const char *bz64_kernel_name(int force_scalar);

#endif
