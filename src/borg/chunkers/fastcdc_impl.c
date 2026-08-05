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
 * All kernels (sequential, blocked scalar, NEON, AVX2, AVX-512) return
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

/* --- blocked scalar (portable C, no intrinsics) ------------------------- */

static int64_t fc_scan_blocked(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
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

static int64_t fc_scan_simd(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    uint64_t fp = *fp_io;
    uint64_t s[8];
    uint64x2_t M12 = {mask << 7, mask << 6};
    uint64x2_t M34 = {mask << 5, mask << 4};
    uint64x2_t M56 = {mask << 3, mask << 2};
    uint64x2_t M78 = {mask << 1, mask};
    size_t i = 0;

    for (; i + 8 <= n; i += 8) {
        fc_block_prefix(gear, p + i, s);
        uint64_t c = fp << 8;
        uint64x2_t C = vdupq_n_u64(c);
        uint64x2_t z12 = vceqzq_u64(vandq_u64(vaddq_u64(C, (uint64x2_t){s[0], s[1]}), M12));
        uint64x2_t z34 = vceqzq_u64(vandq_u64(vaddq_u64(C, (uint64x2_t){s[2], s[3]}), M34));
        uint64x2_t z56 = vceqzq_u64(vandq_u64(vaddq_u64(C, (uint64x2_t){s[4], s[5]}), M56));
        uint64x2_t z78 = vceqzq_u64(vandq_u64(vaddq_u64(C, (uint64x2_t){s[6], s[7]}), M78));
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

static int fc_simd_available(void)
{
    return 1;
}

/* --- AVX2 (x86-64, runtime detected) ------------------------------------ */

#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#define FC_KIND "avx2"

#include <immintrin.h>

__attribute__((target("avx2"))) static int64_t
fc_scan_simd(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    uint64_t fp = *fp_io;
    uint64_t s[8];
    /* _mm256_set_epi64x takes arguments high lane first */
    __m256i M1 = _mm256_set_epi64x((long long)(mask << 4), (long long)(mask << 5),
                                   (long long)(mask << 6), (long long)(mask << 7));
    __m256i M2 = _mm256_set_epi64x((long long)mask, (long long)(mask << 1),
                                   (long long)(mask << 2), (long long)(mask << 3));
    __m256i zero = _mm256_setzero_si256();
    size_t i = 0;

    for (; i + 8 <= n; i += 8) {
        fc_block_prefix(gear, p + i, s);
        uint64_t c = fp << 8;
        __m256i C = _mm256_set1_epi64x((long long)c);
        __m256i H1 = _mm256_add_epi64(C, _mm256_loadu_si256((const __m256i *)&s[0]));
        __m256i H2 = _mm256_add_epi64(C, _mm256_loadu_si256((const __m256i *)&s[4]));
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

/* --- AVX-512 (x86-64, runtime detected) --------------------------------- */

#define FC_KIND_512 "avx512"

/* The same 8-lane candidate test as the AVX2 kernel, in one 512-bit vector:
 * vptestnmq fuses the AND and the ==0 test per lane into a mask register,
 * so the whole test is broadcast + load + add + testn + branch. Only the
 * test narrows; the scalar prefix work (fc_block_prefix) is shared. */
__attribute__((target("avx512f"))) static int64_t
fc_scan_simd512(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    uint64_t fp = *fp_io;
    uint64_t s[8];
    /* _mm512_set_epi64 takes arguments high lane first: lane j = mask << (7-j) */
    __m512i M = _mm512_set_epi64((long long)mask, (long long)(mask << 1),
                                 (long long)(mask << 2), (long long)(mask << 3),
                                 (long long)(mask << 4), (long long)(mask << 5),
                                 (long long)(mask << 6), (long long)(mask << 7));
    size_t i = 0;

    for (; i + 8 <= n; i += 8) {
        fc_block_prefix(gear, p + i, s);
        uint64_t c = fp << 8;
        __m512i H = _mm512_add_epi64(_mm512_set1_epi64((long long)c),
                                     _mm512_loadu_si512((const void *)s));
        if (_mm512_testn_epi64_mask(H, M)) {
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

static int fc_simd_available(void)
{
    /* BORG_FASTCDC_NO_AVX512 caps dispatch at AVX2 (for benchmarking the
     * kernels against each other); like the detection itself it is read
     * once per process, so it must be set before the first chunker use. */
    if (__builtin_cpu_supports("avx512f")) {
        const char *e = getenv("BORG_FASTCDC_NO_AVX512");
        if (e == NULL || e[0] == 0 || strcmp(e, "0") == 0)
            return 2;
    }
    return __builtin_cpu_supports("avx2");
}

#else
#define FC_KIND "blocked"

static int64_t fc_scan_simd(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp_io, uint64_t mask)
{
    return fc_scan_blocked(gear, p, n, fp_io, mask);
}

static int fc_simd_available(void)
{
    return 0;
}

#endif

/* --- dispatch ----------------------------------------------------------- */

/* resolved once (0 = blocked, 1 = FC_KIND, 2 = FC_KIND_512 where defined);
 * a racy double-init writes the same value, so it is benign */
static int fc_use_simd = -1;

int64_t fc_scan(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp, uint64_t mask, int force_scalar)
{
    if (force_scalar)
        return fc_scan_seq(gear, p, n, fp, mask);
    if (fc_use_simd < 0)
        fc_use_simd = fc_simd_available();
#ifdef FC_KIND_512
    if (fc_use_simd == 2)
        return fc_scan_simd512(gear, p, n, fp, mask);
#endif
    if (fc_use_simd)
        return fc_scan_simd(gear, p, n, fp, mask);
    return fc_scan_blocked(gear, p, n, fp, mask);
}

const char *fc_kernel_name(int force_scalar)
{
    if (force_scalar)
        return "scalar";
    if (fc_use_simd < 0)
        fc_use_simd = fc_simd_available();
#ifdef FC_KIND_512
    if (fc_use_simd == 2)
        return FC_KIND_512;
#endif
    return fc_use_simd ? FC_KIND : "blocked";
}
