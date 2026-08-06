/* fastcdc chunker scan kernel, see fastcdc_impl.h and fastcdc.pyx.
 *
 * The sequential Gear loop is
 *     fp = (fp << 1) + gear[b];  cut iff (fp & mask) == 0
 * with mask occupying the HIGH bits of the hash. Because shifts and adds
 * distribute exactly in mod-2^64 arithmetic, a block of 8 positions can be
 * computed and tested in parallel, bit-identically to 8 sequential steps:
 *
 *     h_j  = (fp << j) + sum_{t<=j} gear[b_t] << (j-t)              (j = 1..8)
 *     H_j := h_j << (8-j) = (fp << 8) + S_j
 *     S_j  = sum_{t<=j} u_t,   u_t = gear[b_t] << (8-t)
 *
 * i.e. in the "aligned domain" all 8 hashes share one base (fp << 8) plus a
 * plain prefix sum - the serial dependency chain shrinks from shift+add per
 * byte to shift+add per 8 bytes, and the prefix sums have no serial chain
 * across blocks.
 *
 * Testing: (H_j & (mask << (8-j))) == 0 tests h_j & mask with the top 8-j
 * mask bits dropped (they were shifted out of H_j) - a superset condition:
 * no false negatives, and false positives at ~2^-(maskbits-8+j) per lane,
 * which an exact sequential recheck of the block resolves. The per-lane
 * masks (mask << 7 .. mask << 0) are constants of the scan.
 *
 * All kernels (sequential, blockwise scalar, NEON, AVX2, AVX-512) return
 * bit-identical cut positions and fp values; the chunker's golden tests
 * depend on this. */

#include <stdlib.h>
#include <string.h>

#include "fastcdc_impl.h"

/* --- sequential reference loop (also: block recheck and tail) ----------- */

static int64_t fc_scan_seq(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    uint64_t fp = *fp_io;
    for (size_t i = 0; i < n; i++) {
        fp = (fp << 1) + gear[p[i]];
        if ((fp & mask) == 0) {
            *fp_io = fp;
            return (int64_t)i;
        }
    }
    *fp_io = fp;
    return -1;
}

/* Load the block's 8 gear values (via one 8-byte data load) and compute the
 * aligned-domain prefix sums s[0..7] with a tree (depth ~3 instead of a
 * 7-add chain). Endianness-independent: bytes are extracted by shifting. */
static inline void fc_block_prefix(const uint64_t *gear, const uint8_t *p, uint64_t s[8])
{
    uint64_t w;
    memcpy(&w, p, 8);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    w = __builtin_bswap64(w);
#endif
    uint64_t u1 = gear[(uint8_t)w] << 7;
    uint64_t u2 = gear[(uint8_t)(w >> 8)] << 6;
    uint64_t u3 = gear[(uint8_t)(w >> 16)] << 5;
    uint64_t u4 = gear[(uint8_t)(w >> 24)] << 4;
    uint64_t u5 = gear[(uint8_t)(w >> 32)] << 3;
    uint64_t u6 = gear[(uint8_t)(w >> 40)] << 2;
    uint64_t u7 = gear[(uint8_t)(w >> 48)] << 1;
    uint64_t u8 = gear[(uint8_t)(w >> 56)];
    uint64_t t12 = u1 + u2, t34 = u3 + u4, t56 = u5 + u6, t78 = u7 + u8;
    uint64_t s4 = t12 + t34, s6 = s4 + t56, s8 = s6 + t78;
    s[0] = u1;
    s[1] = t12;
    s[2] = t12 + u3;
    s[3] = s4;
    s[4] = s4 + u5;
    s[5] = s6;
    s[6] = s6 + u7;
    s[7] = s8;
}

/* --- blockwise scalar (portable C, no intrinsics) ------------------------- */

static int64_t fc_scan_blockwise(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    uint64_t fp = *fp_io;
    uint64_t M[8];
    uint64_t s[8];
    size_t i = 0;

    for (int j = 0; j < 8; j++)
        M[j] = mask << (7 - j);
    for (; i + 8 <= n; i += 8) {
        fc_block_prefix(gear, p + i, s);
        uint64_t c = fp << 8;
        uint64_t cand = 0;
        for (int j = 0; j < 8; j++)
            cand |= (((c + s[j]) & M[j]) == 0);
        if (cand) {
            int64_t r = fc_scan_seq(gear, p + i, 8, &fp, mask); /* exact recheck */
            if (r >= 0) {
                *fp_io = fp;
                return (int64_t)i + r;
            }
        } else {
            fp = c + s[7];
        }
    }
    if (i < n) {
        int64_t r = fc_scan_seq(gear, p + i, n - i, &fp, mask);
        if (r >= 0) {
            *fp_io = fp;
            return (int64_t)i + r;
        }
    }
    *fp_io = fp;
    return -1;
}

/* --- NEON (aarch64 baseline, always available) -------------------------- */

#if defined(__aarch64__)
#define FC_KIND "neon"

#include <arm_neon.h>

/* Per lane, "(x & M) == 0" is replaced by "x <= ~M", turning the and plus
 * compare-against-zero into one unsigned compare against a limit computed
 * once per scan.
 *
 * (x & M) == 0 means x's set bits are a subset of ~M's, which implies
 * x <= ~M for any M - so this never loses a cut, whatever the mask looks
 * like. For the contiguous high-bit masks the chunker actually uses (mask
 * has its one-bits at the top and shifting left only drops bits off the top,
 * so ~M is 2^(64-k)-1) the two are exactly equivalent, and this stays the
 * same superset test as the masked form: the block's exact sequential
 * recheck resolves candidates either way. */
static int64_t fc_scan_simd(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    uint64_t fp = *fp_io;
    uint64_t s[8];
    uint64x2_t L12 = {~(mask << 7), ~(mask << 6)};
    uint64x2_t L34 = {~(mask << 5), ~(mask << 4)};
    uint64x2_t L56 = {~(mask << 3), ~(mask << 2)};
    uint64x2_t L78 = {~(mask << 1), ~mask};
    size_t i = 0;

    for (; i + 8 <= n; i += 8) {
        fc_block_prefix(gear, p + i, s);
        uint64_t c = fp << 8;
        uint64x2_t C = vdupq_n_u64(c);
        uint64x2_t z12 = vcgeq_u64(L12, vaddq_u64(C, (uint64x2_t){s[0], s[1]}));
        uint64x2_t z34 = vcgeq_u64(L34, vaddq_u64(C, (uint64x2_t){s[2], s[3]}));
        uint64x2_t z56 = vcgeq_u64(L56, vaddq_u64(C, (uint64x2_t){s[4], s[5]}));
        uint64x2_t z78 = vcgeq_u64(L78, vaddq_u64(C, (uint64x2_t){s[6], s[7]}));
        uint64x2_t any = vorrq_u64(vorrq_u64(z12, z34), vorrq_u64(z56, z78));
        if (vmaxvq_u32(vreinterpretq_u32_u64(any))) {
            int64_t r = fc_scan_seq(gear, p + i, 8, &fp, mask); /* exact recheck */
            if (r >= 0) {
                *fp_io = fp;
                return (int64_t)i + r;
            }
        } else {
            fp = c + s[7];
        }
    }
    if (i < n) {
        int64_t r = fc_scan_seq(gear, p + i, n - i, &fp, mask);
        if (r >= 0) {
            *fp_io = fp;
            return (int64_t)i + r;
        }
    }
    *fp_io = fp;
    return -1;
}


/* --- AVX2 (x86-64, runtime detected) ------------------------------------ */

#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#define FC_KIND "avx2"

#include <immintrin.h>

/* Load the block's 8 gear values (via one 8-byte data load), without the
 * shifts and the prefix sum: the vector kernels do those in the vector
 * domain. Endianness-independent: bytes are extracted by shifting. */
static inline void fc_block_gear(const uint64_t *gear, const uint8_t *p, uint64_t g[8])
{
    uint64_t w;
    memcpy(&w, p, 8);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    w = __builtin_bswap64(w);
#endif
    g[0] = gear[(uint8_t)w];
    g[1] = gear[(uint8_t)(w >> 8)];
    g[2] = gear[(uint8_t)(w >> 16)];
    g[3] = gear[(uint8_t)(w >> 24)];
    g[4] = gear[(uint8_t)(w >> 32)];
    g[5] = gear[(uint8_t)(w >> 40)];
    g[6] = gear[(uint8_t)(w >> 48)];
    g[7] = gear[(uint8_t)(w >> 56)];
}

/* The 8-lane candidate test in two 256-bit vectors, with the aligned domain
 * built in the vector domain: vpsllvq applies the per-lane shifts, then an
 * inclusive prefix sum inside each 4-lane half (two vpermq+vpaddq steps) plus
 * a broadcast of the low half's total into the high half.
 *
 * Only the 8 gear table lookups stay scalar, and they are done one block
 * ahead into a double buffer: a 32-byte vector load placed right after the
 * eight 8-byte scalar stores that filled it cannot use store-to-load
 * forwarding and stalls, twice per block. Loading block i+1 while block i is
 * tested puts a full loop body between the stores and the load, so the stores
 * have retired by then and the stall disappears. Before this, the stalls made
 * the AVX2 kernel slower than the blockwise scalar one. */
__attribute__((target("avx2"))) static int64_t
fc_scan_simd(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    uint64_t fp = *fp_io;
    uint64_t g[16]; /* double buffer: block being tested + block being loaded */
    /* _mm256_set_epi64x takes arguments high lane first */
    const __m256i M1 = _mm256_set_epi64x((long long)(mask << 4), (long long)(mask << 5),
                                         (long long)(mask << 6), (long long)(mask << 7));
    const __m256i M2 = _mm256_set_epi64x((long long)mask, (long long)(mask << 1),
                                         (long long)(mask << 2), (long long)(mask << 3));
    const __m256i SL = _mm256_set_epi64x(4, 5, 6, 7); /* lanes 0..3 <<= 7..4 */
    const __m256i SH = _mm256_set_epi64x(0, 1, 2, 3); /* lanes 4..7 <<= 3..0 */
    const __m256i zero = _mm256_setzero_si256();
    size_t i = 0;
    int cur = 0;

    if (n >= 16) {
        fc_block_gear(gear, p, g);
        for (; i + 16 <= n; i += 8, cur ^= 8) {
            fc_block_gear(gear, p + i + 8, g + (cur ^ 8)); /* one block ahead */
            __m256i lo = _mm256_sllv_epi64(_mm256_loadu_si256((const __m256i *)(g + cur)), SL);
            __m256i hi = _mm256_sllv_epi64(_mm256_loadu_si256((const __m256i *)(g + cur + 4)), SH);
            /* inclusive prefix sum inside each half: rotate the lanes up by 1
             * resp. 2 (vpermq), zero the lanes rotated in, add */
            lo = _mm256_add_epi64(lo, _mm256_blend_epi32(_mm256_permute4x64_epi64(lo, 0x93), zero, 0x03));
            lo = _mm256_add_epi64(lo, _mm256_blend_epi32(_mm256_permute4x64_epi64(lo, 0x4E), zero, 0x0F));
            hi = _mm256_add_epi64(hi, _mm256_blend_epi32(_mm256_permute4x64_epi64(hi, 0x93), zero, 0x03));
            hi = _mm256_add_epi64(hi, _mm256_blend_epi32(_mm256_permute4x64_epi64(hi, 0x4E), zero, 0x0F));
            hi = _mm256_add_epi64(hi, _mm256_permute4x64_epi64(lo, 0xFF)); /* carry s[3] */
            uint64_t c = fp << 8;
            __m256i C = _mm256_set1_epi64x((long long)c);
            __m256i H1 = _mm256_add_epi64(C, lo);
            __m256i H2 = _mm256_add_epi64(C, hi);
            __m256i z1 = _mm256_cmpeq_epi64(_mm256_and_si256(H1, M1), zero);
            __m256i z2 = _mm256_cmpeq_epi64(_mm256_and_si256(H2, M2), zero);
            __m256i any = _mm256_or_si256(z1, z2);
            if (!_mm256_testz_si256(any, any)) {
                int64_t r = fc_scan_seq(gear, p + i, 8, &fp, mask); /* exact recheck */
                if (r >= 0) {
                    *fp_io = fp;
                    return (int64_t)i + r;
                }
            } else {
                fp = c + (uint64_t)_mm_cvtsi128_si64(_mm256_castsi256_si128(
                             _mm256_permute4x64_epi64(hi, 0xFF))); /* s[7] */
            }
        }
    }
    if (i < n) { /* up to 15 bytes here (one block more than the scalar kernels) */
        int64_t r = fc_scan_seq(gear, p + i, n - i, &fp, mask);
        if (r >= 0) {
            *fp_io = fp;
            return (int64_t)i + r;
        }
    }
    *fp_io = fp;
    return -1;
}

/* --- AVX-512 (x86-64, runtime detected) --------------------------------- */

#define FC_KIND_512 "avx512"

/* The same 8-lane candidate test as the AVX2 kernel, but the aligned domain
 * fits in one 512-bit vector: vpsllvq applies the per-lane shifts (lane j <<
 * (7-j)), three valignq+vpaddq steps turn the shifted gear values into the
 * inclusive prefix sums s[0..7] in one pass instead of two halves plus a
 * carry, and vptestnmq fuses the AND and the ==0 test into a mask register.
 *
 * The gear lookups are pipelined one block ahead exactly as in the AVX2
 * kernel above, for the same store-to-load forwarding reason.
 *
 * The serial chain stays short: only fp = c + s[7] (scalar add + shift per
 * 8 bytes) is carried across blocks, and s[7] is read out of the vector with
 * vpermq off that chain. */
__attribute__((target("avx512f"))) static int64_t
fc_scan_simd512(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    uint64_t fp = *fp_io;
    uint64_t g[16]; /* double buffer: block being tested + block being loaded */
    /* _mm512_set_epi64 takes arguments high lane first: lane j = mask << (7-j) */
    const __m512i M = _mm512_set_epi64((long long)mask, (long long)(mask << 1),
                                       (long long)(mask << 2), (long long)(mask << 3),
                                       (long long)(mask << 4), (long long)(mask << 5),
                                       (long long)(mask << 6), (long long)(mask << 7));
    const __m512i SH = _mm512_set_epi64(0, 1, 2, 3, 4, 5, 6, 7); /* lane j <<= 7-j */
    const __m512i Z = _mm512_setzero_si512();
    size_t i = 0;
    int cur = 0;

    if (n >= 16) {
        fc_block_gear(gear, p, g);
        for (; i + 16 <= n; i += 8, cur ^= 8) {
            fc_block_gear(gear, p + i + 8, g + (cur ^ 8)); /* one block ahead */
            /* u = shifted gear values, then the inclusive prefix sum over the
             * 8 lanes (Hillis-Steele: shift lanes up by 1, 2, 4 and add;
             * _mm512_alignr_epi64(u, Z, 8-k) shifts up by k, zero-filling) */
            __m512i u = _mm512_sllv_epi64(_mm512_loadu_si512((const void *)(g + cur)), SH);
            u = _mm512_add_epi64(u, _mm512_alignr_epi64(u, Z, 7));
            u = _mm512_add_epi64(u, _mm512_alignr_epi64(u, Z, 6));
            u = _mm512_add_epi64(u, _mm512_alignr_epi64(u, Z, 4));
            uint64_t c = fp << 8;
            __m512i H = _mm512_add_epi64(_mm512_set1_epi64((long long)c), u);
            if (_mm512_testn_epi64_mask(H, M)) {
                int64_t r = fc_scan_seq(gear, p + i, 8, &fp, mask); /* exact recheck */
                if (r >= 0) {
                    *fp_io = fp;
                    return (int64_t)i + r;
                }
            } else {
                fp = c + (uint64_t)_mm_cvtsi128_si64(_mm512_castsi512_si128(
                             _mm512_permutexvar_epi64(_mm512_set1_epi64(7), u))); /* s[7] */
            }
        }
    }
    if (i < n) { /* up to 15 bytes here (one block more than the other kernels) */
        int64_t r = fc_scan_seq(gear, p + i, n - i, &fp, mask);
        if (r >= 0) {
            *fp_io = fp;
            return (int64_t)i + r;
        }
    }
    *fp_io = fp;
    return -1;
}


#else
#define FC_KIND "blockwise"

static int64_t fc_scan_simd(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    return fc_scan_blockwise(gear, p, n, fp_io, mask);
}


#endif

/* --- kernel selection --------------------------------------------------- */

const char *fc_kernel_names(void)
{
#if defined(__aarch64__)
    return "neon,blockwise,scalar";
#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
    return "avx512,avx2,blockwise,scalar";
#else
    return "blockwise,scalar";
#endif
}

int fc_kernel_select(const char *name, int *out_id)
{
    if (strcmp(name, "scalar") == 0) {
        *out_id = FC_K_SCALAR;
        return FC_KSEL_OK;
    }
    if (strcmp(name, "blockwise") == 0) {
        *out_id = FC_K_BLOCKWISE;
        return FC_KSEL_OK;
    }
#if defined(__aarch64__)
    if (strcmp(name, "neon") == 0) {
        *out_id = FC_K_VECTOR; /* baseline on aarch64, always runnable */
        return FC_KSEL_OK;
    }
#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
    if (strcmp(name, "avx2") == 0) {
        if (!__builtin_cpu_supports("avx2"))
            return FC_KSEL_NOCPU;
        *out_id = FC_K_VECTOR;
        return FC_KSEL_OK;
    }
    if (strcmp(name, "avx512") == 0) {
#ifndef FC_KIND_512
        return FC_KSEL_NOTBUILT; /* compiler too old for the target attribute */
#else
        if (!__builtin_cpu_supports("avx512f"))
            return FC_KSEL_NOCPU;
        *out_id = FC_K_VECTOR512;
        return FC_KSEL_OK;
#endif
    }
#endif
    return FC_KSEL_UNKNOWN;
}

/* --- dispatch ----------------------------------------------------------- */

int64_t fc_scan(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp, uint64_t mask, int kernel)
{
    switch (kernel) {
    case FC_K_SCALAR:
        return fc_scan_seq(gear, p, n, fp, mask);
    case FC_K_BLOCKWISE:
        return fc_scan_blockwise(gear, p, n, fp, mask);
#ifdef FC_KIND_512
    case FC_K_VECTOR512:
        return fc_scan_simd512(gear, p, n, fp, mask);
#endif
    default:
        return fc_scan_simd(gear, p, n, fp, mask);
    }
}

const char *fc_kernel_name(int kernel)
{
    switch (kernel) {
    case FC_K_SCALAR:
        return "scalar";
    case FC_K_BLOCKWISE:
        return "blockwise";
#ifdef FC_KIND_512
    case FC_K_VECTOR512:
        return FC_KIND_512;
#endif
    default:
        return FC_KIND;
    }
}
