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

/* Scan kernel ids. Which names map onto them depends on the build: "neon"
 * exists only on aarch64, "avx2"/"avx512" only on x86-64.
 *
 * FC_K_SCALAR, the plain sequential loop, is id 0 and the one the others are
 * checked against. Which kernel is fastest is not predictable from the
 * instruction set (on an Apple M3 the NEON kernel beats the sequential loop
 * 2.1x; with gcc on a Zen 4 the sequential loop beats AVX-512 by 1.7x), so
 * fc_kernel_default() encodes what was measured per platform rather than
 * "the widest vectors this CPU has". */
#define FC_K_SCALAR 0    /* sequential reference loop */
#define FC_K_BLOCKWISE 1 /* portable 8-lane C */
#define FC_K_VECTOR 2    /* the platform's vector kernel: neon or avx2 */
#define FC_K_VECTOR512 3 /* avx512 */

/* Results of fc_kernel_select(). */
#define FC_KSEL_OK 0
#define FC_KSEL_UNKNOWN 1  /* not a kernel name on this platform */
#define FC_KSEL_NOTBUILT 2 /* known, but not compiled into this binary */
#define FC_KSEL_NOCPU 3    /* known and built, but this CPU cannot run it */

/* Resolve a kernel name for this build. On FC_KSEL_OK the id is stored in
 * *out_id, otherwise *out_id is left alone. The three failures are kept apart
 * because they need different fixes: a typo, too old a compiler, or the wrong
 * CPU. */
int fc_kernel_select(const char *name, int *out_id);

/* Comma-separated list of the kernel names this build accepts, for error
 * messages. Names a CPU cannot run are still listed. */
const char *fc_kernel_names(void);

/* The kernel to run when the caller did not ask for a specific one, see
 * fc_kernel_default() in fastcdc_impl.c for what is chosen where. */
int fc_kernel_default(void);

/* Scan up to n positions: for i = 0..n-1 advance fp = (fp << 1) + gear[p[i]]
 * and test (fp & mask) == 0.
 * Returns the first i that matched (fp is left at position i), or -1 if none
 * matched (fp is left at position n-1).
 * gear: the keyed 256-entry table. kernel is one of FC_K_*; callers are
 * expected to have validated it with fc_kernel_select(), an unrunnable one
 * falls back to the vector kernel rather than crashing.
 * All kernels return bit-identical results. */
int64_t fc_scan(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp, uint64_t mask, int kernel);

/* Name of the kernel <kernel> selects. */
const char *fc_kernel_name(int kernel);

#endif
