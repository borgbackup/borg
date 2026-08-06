/* buzhash64 chunker scan kernel, see buzhash64_impl.h and buzhash64.pyx.
 *
 * The sequential loop (test-then-update) is
 *     while (sum & mask) != 0:
 *         sum = ROTL1(sum) ^ ROTL_lenmod(T[out]) ^ T[in]
 * with mask occupying the LOW bits. The update is GF(2)-linear and the
 * rotation is a bijection, so a block of 8 positions can be computed and
 * tested in parallel, bit-identically and - unlike the fastcdc kernel's
 * pre-filter - with an EXACT test:
 *
 *     sum_j = R^j(sum_0) ^ XOR_{t<j} R^(j-1-t)(D_t),   D_t = Trot[out_t] ^ T[in_t]
 *     H_j  := R^(8-j)(sum_j) = R^8(sum_0) ^ S_j
 *     S_j   = XOR_{t<j} u_t,   u_t = R^(7-t)(D_t)      (plain prefix XOR, depth-3 tree)
 *     (sum_j & mask) == 0  <=>  (H_j & R^(8-j)(mask)) == 0
 *
 * (rotation loses no bits, so the rotated-mask test is exact - no false
 * positives, no false negatives). On a hit, the block is re-scanned with the
 * sequential loop to locate the earliest position and produce the exit sum;
 * on no hit, sum_8 = H_8 continues the chain exactly.
 *
 * Trot[b] = ROTL(T[b], window_size % 64) is precomputed by the caller, which
 * also removes one rotate per byte from the sequential path.
 *
 * Kernel dispatch: AVX-512 or AVX2 on x86-64 (runtime-detected), blockwise
 * scalar everywhere else, including aarch64 by default - its NEON kernel is
 * selectable by name but not auto-selected, see the note above it.
 * All kernels return bit-identical results. */

#include <stdlib.h>
#include <string.h>

#include "buzhash64_impl.h"

#define BZ_ROTL(x, k) (((x) << ((k) & 63)) | ((x) >> ((64 - (k)) & 63)))

/* --- sequential reference loop (also: block re-scan and tail) ----------- */

static size_t bz64_scan_seq(const uint64_t *T, const uint64_t *Trot,
                            const uint8_t *pr, const uint8_t *pa,
                            size_t n, uint64_t *sum_io, uint64_t mask)
{
    uint64_t sum = *sum_io;
    size_t j = 0;
    while (j < n && (sum & mask) != 0) {
        sum = BZ_ROTL(sum, 1) ^ Trot[pr[j]] ^ T[pa[j]];
        j++;
    }
    *sum_io = sum;
    return j;
}

/* Load the block's 8 out/in byte pairs (via two 8-byte data loads) and
 * compute the aligned-domain prefix XORs s[0..7] with a depth-3 tree.
 * Endianness-independent: bytes are extracted by shifting. */
static inline void bz64_block_prefix(const uint64_t *T, const uint64_t *Trot,
                                     const uint8_t *pr, const uint8_t *pa, uint64_t s[8])
{
    uint64_t wr, wa;
    memcpy(&wr, pr, 8);
    memcpy(&wa, pa, 8);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    wr = __builtin_bswap64(wr);
    wa = __builtin_bswap64(wa);
#endif
    uint64_t u0 = BZ_ROTL(Trot[(uint8_t)wr] ^ T[(uint8_t)wa], 7);
    uint64_t u1 = BZ_ROTL(Trot[(uint8_t)(wr >> 8)] ^ T[(uint8_t)(wa >> 8)], 6);
    uint64_t u2 = BZ_ROTL(Trot[(uint8_t)(wr >> 16)] ^ T[(uint8_t)(wa >> 16)], 5);
    uint64_t u3 = BZ_ROTL(Trot[(uint8_t)(wr >> 24)] ^ T[(uint8_t)(wa >> 24)], 4);
    uint64_t u4 = BZ_ROTL(Trot[(uint8_t)(wr >> 32)] ^ T[(uint8_t)(wa >> 32)], 3);
    uint64_t u5 = BZ_ROTL(Trot[(uint8_t)(wr >> 40)] ^ T[(uint8_t)(wa >> 40)], 2);
    uint64_t u6 = BZ_ROTL(Trot[(uint8_t)(wr >> 48)] ^ T[(uint8_t)(wa >> 48)], 1);
    uint64_t u7 = Trot[(uint8_t)(wr >> 56)] ^ T[(uint8_t)(wa >> 56)];
    uint64_t t01 = u0 ^ u1, t23 = u2 ^ u3, t45 = u4 ^ u5, t67 = u6 ^ u7;
    uint64_t s4 = t01 ^ t23, s6 = s4 ^ t45, s8 = s6 ^ t67;
    s[0] = u0;
    s[1] = t01;
    s[2] = t01 ^ u2;
    s[3] = s4;
    s[4] = s4 ^ u4;
    s[5] = s6;
    s[6] = s6 ^ u6;
    s[7] = s8;
}

/* --- blockwise scalar (the default kernel) --------------------------------- */

static size_t bz64_scan_blockwise(const uint64_t *T, const uint64_t *Trot,
                                const uint8_t *pr, const uint8_t *pa,
                                size_t n, uint64_t *sum_io, uint64_t mask)
{
    uint64_t sum = *sum_io;
    uint64_t M[8], s[8];
    size_t j = 0;

    for (int k = 0; k < 8; k++)
        M[k] = BZ_ROTL(mask, 7 - k);
    while (j + 8 <= n && (sum & mask) != 0) {
        bz64_block_prefix(T, Trot, pr + j, pa + j, s);
        uint64_t c = BZ_ROTL(sum, 8);
        uint64_t hit = 0;
        for (int k = 0; k < 8; k++)
            hit |= (((c ^ s[k]) & M[k]) == 0);
        if (hit) {
            size_t r = bz64_scan_seq(T, Trot, pr + j, pa + j, 8, &sum, mask); /* exact re-scan */
            *sum_io = sum;
            return j + r;
        }
        sum = c ^ s[7]; /* = sum_8 exactly */
        j += 8;
    }
    if (j < n)
        j += bz64_scan_seq(T, Trot, pr + j, pa + j, n - j, &sum, mask);
    *sum_io = sum;
    return j;
}

/* --- NEON (aarch64) ------------------------------------------------------
 *
 * Nothing selects this by default (the default is the sequential kernel
 * everywhere); BORG_BUZHASH64_KERNEL=neon selects it. On an Apple M3 Pro it
 * loses to the blockwise kernel - 2590 vs 2360 MB/s, the same ~9% gap at
 * every mask size from 17 to 23 bits - so it is not the one to reach for
 * there.
 *
 * Why it loses there: the 16 table lookups per block have to happen in
 * general registers (NEON has no gather), so the vector form only ADDS the
 * move to the SIMD side plus a cross-lane reduce (umaxv) before the loop
 * branch can resolve - all it saves is the 8-lane test, three cheap ops per
 * lane, which Apple's very wide scalar ALUs retire at more than one lane per
 * cycle anyway. fastcdc keeps NEON as its default because its per-lane test
 * work is larger (add plus per-lane shifted masks), enough to pay for the
 * trip; there it wins by 2x.
 *
 * It is kept because that reasoning is about core width, and the measurement
 * comes from the widest scalar ARM core there is. Neoverse (Graviton,
 * Ampere), Cortex-A7x and friends are 3-4 wide on the scalar side with
 * comparatively healthy NEON, which is exactly where this should get
 * competitive - on this machine's much narrower E-cores the 9% gap already
 * collapses into measurement noise. If you have such hardware, compare
 * BORG_BUZHASH64_KERNEL=neon against =blockwise and please report. */

#if defined(__aarch64__)
#define BZ_KIND "neon"

#include <arm_neon.h>

static size_t bz64_scan_simd(const uint64_t *T, const uint64_t *Trot,
                             const uint8_t *pr, const uint8_t *pa,
                             size_t n, uint64_t *sum_io, uint64_t mask)
{
    uint64_t sum = *sum_io;
    uint64_t s[8];
    size_t j = 0;
    uint64x2_t M12 = {BZ_ROTL(mask, 7), BZ_ROTL(mask, 6)};
    uint64x2_t M34 = {BZ_ROTL(mask, 5), BZ_ROTL(mask, 4)};
    uint64x2_t M56 = {BZ_ROTL(mask, 3), BZ_ROTL(mask, 2)};
    uint64x2_t M78 = {BZ_ROTL(mask, 1), mask};

    while (j + 8 <= n && (sum & mask) != 0) {
        bz64_block_prefix(T, Trot, pr + j, pa + j, s);
        uint64_t c = BZ_ROTL(sum, 8);
        uint64x2_t Cv = vdupq_n_u64(c);
        uint64x2_t z12 = vceqzq_u64(vandq_u64(veorq_u64(Cv, (uint64x2_t){s[0], s[1]}), M12));
        uint64x2_t z34 = vceqzq_u64(vandq_u64(veorq_u64(Cv, (uint64x2_t){s[2], s[3]}), M34));
        uint64x2_t z56 = vceqzq_u64(vandq_u64(veorq_u64(Cv, (uint64x2_t){s[4], s[5]}), M56));
        uint64x2_t z78 = vceqzq_u64(vandq_u64(veorq_u64(Cv, (uint64x2_t){s[6], s[7]}), M78));
        uint64x2_t any = vorrq_u64(vorrq_u64(z12, z34), vorrq_u64(z56, z78));
        if (vmaxvq_u32(vreinterpretq_u32_u64(any))) {
            size_t r = bz64_scan_seq(T, Trot, pr + j, pa + j, 8, &sum, mask); /* exact re-scan */
            *sum_io = sum;
            return j + r;
        }
        sum = c ^ s[7];
        j += 8;
    }
    if (j < n)
        j += bz64_scan_seq(T, Trot, pr + j, pa + j, n - j, &sum, mask);
    *sum_io = sum;
    return j;
}


/* --- AVX2 (x86-64, runtime detected) ------------------------------------ */

#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#define BZ_KIND "avx2"

#include <immintrin.h>

/* Load the block's 8 per-byte deltas D_t = Trot[out_t] ^ T[in_t] (via two
 * 8-byte data loads), without the rotations and the prefix XOR: the vector
 * kernels do those in the vector domain. Endianness-independent. */
static inline void bz64_block_delta(const uint64_t *T, const uint64_t *Trot,
                                    const uint8_t *pr, const uint8_t *pa, uint64_t d[8])
{
    uint64_t wr, wa;
    memcpy(&wr, pr, 8);
    memcpy(&wa, pa, 8);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    wr = __builtin_bswap64(wr);
    wa = __builtin_bswap64(wa);
#endif
    d[0] = Trot[(uint8_t)wr] ^ T[(uint8_t)wa];
    d[1] = Trot[(uint8_t)(wr >> 8)] ^ T[(uint8_t)(wa >> 8)];
    d[2] = Trot[(uint8_t)(wr >> 16)] ^ T[(uint8_t)(wa >> 16)];
    d[3] = Trot[(uint8_t)(wr >> 24)] ^ T[(uint8_t)(wa >> 24)];
    d[4] = Trot[(uint8_t)(wr >> 32)] ^ T[(uint8_t)(wa >> 32)];
    d[5] = Trot[(uint8_t)(wr >> 40)] ^ T[(uint8_t)(wa >> 40)];
    d[6] = Trot[(uint8_t)(wr >> 48)] ^ T[(uint8_t)(wa >> 48)];
    d[7] = Trot[(uint8_t)(wr >> 56)] ^ T[(uint8_t)(wa >> 56)];
}

/* AVX2 has no variable rotate, so ROTL(v, k) is built from a variable left
 * and right shift. The k = 0 lane needs a 64-bit right shift, which
 * vpsrlvq defines as zero - exactly what (v << 0) | 0 = v needs. */
__attribute__((target("avx2"))) static inline __m256i bz64_rotl4(__m256i v, __m256i k, __m256i kc)
{
    return _mm256_or_si256(_mm256_sllv_epi64(v, k), _mm256_srlv_epi64(v, kc));
}

/* The 8-lane test in two 256-bit vectors, with the aligned domain built in
 * the vector domain: per-lane rotations, then a prefix XOR inside each 4-lane
 * half (two vpermq+vpxor steps) plus a broadcast of the low half's total into
 * the high half.
 *
 * Only the 2x8 table lookups stay scalar, and they are done one block ahead
 * into a double buffer: a 32-byte vector load placed right after the eight
 * 8-byte scalar stores that filled it cannot use store-to-load forwarding and
 * stalls, twice per block. Loading block j+1 while block j is tested puts a
 * full loop body between the stores and the load, so the stall disappears. */
__attribute__((target("avx2"))) static size_t
bz64_scan_simd(const uint64_t *T, const uint64_t *Trot,
               const uint8_t *pr, const uint8_t *pa,
               size_t n, uint64_t *sum_io, uint64_t mask)
{
    uint64_t sum = *sum_io;
    uint64_t d[16]; /* double buffer: block being tested + block being loaded */
    size_t j = 0;
    int cur = 0;
    /* _mm256_set_epi64x takes arguments high lane first */
    const __m256i M1 = _mm256_set_epi64x((long long)BZ_ROTL(mask, 4), (long long)BZ_ROTL(mask, 5),
                                         (long long)BZ_ROTL(mask, 6), (long long)BZ_ROTL(mask, 7));
    const __m256i M2 = _mm256_set_epi64x((long long)mask, (long long)BZ_ROTL(mask, 1),
                                         (long long)BZ_ROTL(mask, 2), (long long)BZ_ROTL(mask, 3));
    const __m256i KL = _mm256_set_epi64x(4, 5, 6, 7); /* lanes 0..3 rotate by 7..4 */
    const __m256i KH = _mm256_set_epi64x(0, 1, 2, 3); /* lanes 4..7 rotate by 3..0 */
    const __m256i KLC = _mm256_set_epi64x(60, 59, 58, 57); /* 64 - KL */
    const __m256i KHC = _mm256_set_epi64x(64, 63, 62, 61); /* 64 - KH */
    const __m256i zero = _mm256_setzero_si256();

    if (n >= 16 && (sum & mask) != 0) {
        bz64_block_delta(T, Trot, pr, pa, d);
        while (j + 16 <= n && (sum & mask) != 0) {
            bz64_block_delta(T, Trot, pr + j + 8, pa + j + 8, d + (cur ^ 8)); /* one block ahead */
            __m256i lo = bz64_rotl4(_mm256_loadu_si256((const __m256i *)(d + cur)), KL, KLC);
            __m256i hi = bz64_rotl4(_mm256_loadu_si256((const __m256i *)(d + cur + 4)), KH, KHC);
            /* prefix XOR inside each half: rotate the lanes up by 1 resp. 2
             * (vpermq), zero the lanes rotated in, XOR */
            lo = _mm256_xor_si256(lo, _mm256_blend_epi32(_mm256_permute4x64_epi64(lo, 0x93), zero, 0x03));
            lo = _mm256_xor_si256(lo, _mm256_blend_epi32(_mm256_permute4x64_epi64(lo, 0x4E), zero, 0x0F));
            hi = _mm256_xor_si256(hi, _mm256_blend_epi32(_mm256_permute4x64_epi64(hi, 0x93), zero, 0x03));
            hi = _mm256_xor_si256(hi, _mm256_blend_epi32(_mm256_permute4x64_epi64(hi, 0x4E), zero, 0x0F));
            hi = _mm256_xor_si256(hi, _mm256_permute4x64_epi64(lo, 0xFF)); /* carry s[3] */
            uint64_t c = BZ_ROTL(sum, 8);
            __m256i C = _mm256_set1_epi64x((long long)c);
            __m256i H1 = _mm256_xor_si256(C, lo);
            __m256i H2 = _mm256_xor_si256(C, hi);
            __m256i z1 = _mm256_cmpeq_epi64(_mm256_and_si256(H1, M1), zero);
            __m256i z2 = _mm256_cmpeq_epi64(_mm256_and_si256(H2, M2), zero);
            __m256i any = _mm256_or_si256(z1, z2);
            if (!_mm256_testz_si256(any, any)) {
                size_t r = bz64_scan_seq(T, Trot, pr + j, pa + j, 8, &sum, mask); /* exact re-scan */
                *sum_io = sum;
                return j + r;
            }
            sum = c ^ (uint64_t)_mm_cvtsi128_si64(_mm256_castsi256_si128(
                          _mm256_permute4x64_epi64(hi, 0xFF))); /* s[7] */
            j += 8;
            cur ^= 8;
        }
    }
    if (j < n) /* up to 15 bytes here (one block more than the scalar kernels) */
        j += bz64_scan_seq(T, Trot, pr + j, pa + j, n - j, &sum, mask);
    *sum_io = sum;
    return j;
}

/* --- AVX-512 (x86-64, runtime detected) ---------------------------------- */

#define BZ_KIND_512 "avx512"

/* The same 8-lane test as the AVX2 kernel, but the aligned domain fits in one
 * 512-bit vector: vprolvq applies the per-lane rotations (lane k by 7-k) in
 * one instruction, three valignq+vpxorq steps turn the rotated deltas into
 * the prefix XORs s[0..7] in one pass instead of two halves plus a carry, and
 * vptestnmq fuses the AND and the ==0 test into a mask register.
 *
 * The table lookups are pipelined one block ahead exactly as in the AVX2
 * kernel above, for the same store-to-load forwarding reason. */
__attribute__((target("avx512f"))) static size_t
bz64_scan_simd512(const uint64_t *T, const uint64_t *Trot,
                  const uint8_t *pr, const uint8_t *pa,
                  size_t n, uint64_t *sum_io, uint64_t mask)
{
    uint64_t sum = *sum_io;
    uint64_t d[16]; /* double buffer: block being tested + block being loaded */
    size_t j = 0;
    int cur = 0;
    /* _mm512_set_epi64 takes arguments high lane first: lane k = ROTL(mask, 7-k) */
    const __m512i M = _mm512_set_epi64((long long)mask, (long long)BZ_ROTL(mask, 1),
                                       (long long)BZ_ROTL(mask, 2), (long long)BZ_ROTL(mask, 3),
                                       (long long)BZ_ROTL(mask, 4), (long long)BZ_ROTL(mask, 5),
                                       (long long)BZ_ROTL(mask, 6), (long long)BZ_ROTL(mask, 7));
    const __m512i RT = _mm512_set_epi64(0, 1, 2, 3, 4, 5, 6, 7); /* lane k: ROTL by 7-k */
    const __m512i Z = _mm512_setzero_si512();

    if (n >= 16 && (sum & mask) != 0) {
        bz64_block_delta(T, Trot, pr, pa, d);
        while (j + 16 <= n && (sum & mask) != 0) {
            bz64_block_delta(T, Trot, pr + j + 8, pa + j + 8, d + (cur ^ 8)); /* one block ahead */
            /* u = rotated deltas, then the prefix XOR over the 8 lanes
             * (shift lanes up by 1, 2, 4 and XOR; _mm512_alignr_epi64(u, Z,
             * 8-k) shifts up by k, zero-filling) */
            __m512i u = _mm512_rolv_epi64(_mm512_loadu_si512((const void *)(d + cur)), RT);
            u = _mm512_xor_si512(u, _mm512_alignr_epi64(u, Z, 7));
            u = _mm512_xor_si512(u, _mm512_alignr_epi64(u, Z, 6));
            u = _mm512_xor_si512(u, _mm512_alignr_epi64(u, Z, 4));
            uint64_t c = BZ_ROTL(sum, 8);
            __m512i H = _mm512_xor_si512(_mm512_set1_epi64((long long)c), u);
            if (_mm512_testn_epi64_mask(H, M)) {
                size_t r = bz64_scan_seq(T, Trot, pr + j, pa + j, 8, &sum, mask); /* exact re-scan */
                *sum_io = sum;
                return j + r;
            }
            sum = c ^ (uint64_t)_mm_cvtsi128_si64(_mm512_castsi512_si128(
                          _mm512_permutexvar_epi64(_mm512_set1_epi64(7), u))); /* s[7] */
            j += 8;
            cur ^= 8;
        }
    }
    if (j < n) /* up to 15 bytes here (one block more than the other kernels) */
        j += bz64_scan_seq(T, Trot, pr + j, pa + j, n - j, &sum, mask);
    *sum_io = sum;
    return j;
}


#else
#define BZ_KIND "blockwise"

static size_t bz64_scan_simd(const uint64_t *T, const uint64_t *Trot,
                             const uint8_t *pr, const uint8_t *pa,
                             size_t n, uint64_t *sum_io, uint64_t mask)
{
    return bz64_scan_blockwise(T, Trot, pr, pa, n, sum_io, mask);
}


#endif

/* --- kernel selection --------------------------------------------------- */

const char *bz64_kernel_names(void)
{
#if defined(__aarch64__)
    return "neon,blockwise,scalar";
#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
    return "avx512,avx2,blockwise,scalar";
#else
    return "blockwise,scalar";
#endif
}

int bz64_kernel_select(const char *name, int *out_id)
{
    if (strcmp(name, "scalar") == 0) {
        *out_id = BZ_K_SCALAR;
        return BZ_KSEL_OK;
    }
    if (strcmp(name, "blockwise") == 0) {
        *out_id = BZ_K_BLOCKWISE;
        return BZ_KSEL_OK;
    }
#if defined(__aarch64__)
    if (strcmp(name, "neon") == 0) {
        *out_id = BZ_K_VECTOR; /* baseline on aarch64, always runnable */
        return BZ_KSEL_OK;
    }
#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
    if (strcmp(name, "avx2") == 0) {
        if (!__builtin_cpu_supports("avx2"))
            return BZ_KSEL_NOCPU;
        *out_id = BZ_K_VECTOR;
        return BZ_KSEL_OK;
    }
    if (strcmp(name, "avx512") == 0) {
#ifndef BZ_KIND_512
        return BZ_KSEL_NOTBUILT; /* compiler too old for the target attribute */
#else
        if (!__builtin_cpu_supports("avx512f"))
            return BZ_KSEL_NOCPU;
        *out_id = BZ_K_VECTOR512;
        return BZ_KSEL_OK;
#endif
    }
#endif
    return BZ_KSEL_UNKNOWN;
}

/* --- dispatch ----------------------------------------------------------- */

size_t bz64_scan(const uint64_t *table, const uint64_t *table_rot,
                 const uint8_t *p_rem, const uint8_t *p_add,
                 size_t n, uint64_t *sum, uint64_t mask, int kernel)
{
    switch (kernel) {
    case BZ_K_SCALAR:
        return bz64_scan_seq(table, table_rot, p_rem, p_add, n, sum, mask);
    case BZ_K_BLOCKWISE:
        return bz64_scan_blockwise(table, table_rot, p_rem, p_add, n, sum, mask);
#ifdef BZ_KIND_512
    case BZ_K_VECTOR512:
        return bz64_scan_simd512(table, table_rot, p_rem, p_add, n, sum, mask);
#endif
    default:
        return bz64_scan_simd(table, table_rot, p_rem, p_add, n, sum, mask);
    }
}

const char *bz64_kernel_name(int kernel)
{
    switch (kernel) {
    case BZ_K_SCALAR:
        return "scalar";
    case BZ_K_BLOCKWISE:
        return "blockwise";
#ifdef BZ_KIND_512
    case BZ_K_VECTOR512:
        return BZ_KIND_512;
#endif
    default:
        return BZ_KIND;
    }
}
