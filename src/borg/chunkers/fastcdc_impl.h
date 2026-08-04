/* fastcdc chunker scan kernel: the Gear rolling hash inner loop, with
 * SIMD-accelerated implementations that are bit-identical to the plain
 * sequential loop (see fastcdc_impl.c for the algebra).
 *
 * The cut decision granularity stays at 1 byte: every position is tested
 * against the mask, exactly as in the sequential loop. */

#ifndef BORG_FASTCDC_IMPL_H
#define BORG_FASTCDC_IMPL_H

#include <stdint.h>
#include <stddef.h>

/* Scan up to n positions: for i = 0..n-1 advance fp = (fp << 1) + gear[p[i]]
 * and test (fp & mask) == 0.
 * Returns the first i that matched (fp is left at position i), or -1 if none
 * matched (fp is left at position n-1).
 * gear: the keyed 256-entry table. force_scalar != 0 selects the sequential
 * reference loop (for tests); otherwise the best kernel for this CPU is used.
 * All kernels return bit-identical results. */
int64_t fc_scan(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp, uint64_t mask, int force_scalar);

/* Name of the kernel fc_scan would use: "neon", "avx2", "blocked" or "scalar". */
const char *fc_kernel_name(int force_scalar);

#endif
