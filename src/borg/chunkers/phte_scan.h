/* Scan template for the UHF-then-PRF ("Chk-PHTE") chunker kernels.
 *
 * Include this once per kernel .c file, after including phte_core.h, defining
 * the kernel's context struct (first member: PHTE_BASE base) and its rolling
 * hash as static inline functions, and defining:
 *
 *   PH_PREFIX     token prefix of the kernel's exported names, e.g. ra_
 *   PH_CTX        the kernel's context struct type, e.g. RA_CTX
 *   PH_ROLL       (c, d, byte_out, byte_in) -> digest advanced by one byte
 *   PH_ROLL2      (c, d, o0, o1, i0, i1)    -> digest advanced by two bytes
 *   PH_DIGEST64   (c, q)                    -> digest of the 64 bytes at q
 *
 * The rolling functions are expanded inline here, so each kernel gets its own
 * fully specialized scan loops - identical code generation to writing them
 * out per kernel, which is what this template replaced.
 *
 * It defines the exported <prefix>scan() plus its internal helpers:
 *
 *  - a portable path batching digests through OpenSSL EVP AES-128-ECB,
 *  - a hardware path using AES instructions directly (arm64 crypto extension,
 *    x86-64 AES-NI), which interleaves the serial rolling-hash chain with
 *    pipelined AES so the AES work is (mostly) hidden behind it,
 *  - a VAES/AVX-512 variant of the x86-64 hardware path (runtime-detected)
 *    encrypting 4 AES blocks per instruction.
 *
 * All paths produce bit-identical cut points.
 */

#define PH_CAT2(a, b) a##b
#define PH_CAT(a, b) PH_CAT2(a, b)
#define PH_FN(name) PH_CAT(PH_PREFIX, name)

/* sub-batch size (blocks); 512 * 16 B = 8 KiB in/out buffers on the stack */
#define PH_SB 512

/* --- two-lane digest fill (shared by the portable path) ----------------- */

/* Compute the digests for positions [0, m), writing each as an AES input
 * block (digest LE in bytes 0..7; bytes 8..15 must already be zero) into inb.
 * On entry *d_io is the digest at position -1; on return, at position m-1.
 * Uses two independent even/odd lanes advancing with stride 2 so the two
 * dependency chains overlap; bit-identical to m single PH_ROLL steps. */
static inline void PH_FN(fill2)(const PH_CTX *c, const uint8_t *q, const uint8_t *qo,
                                size_t m, uint64_t *d_io, uint8_t *inb)
{
    uint64_t d = *d_io, da, db;
    size_t i;

    if (m == 1) {
        d = PH_ROLL(c, d, qo[0], q[0]);
        phte_store_le64(inb, d);
        *d_io = d;
        return;
    }
    db = PH_ROLL(c, d, qo[0], q[0]);                /* even lane: d_0 */
    da = PH_ROLL2(c, d, qo[0], qo[1], q[0], q[1]);  /* odd lane:  d_1 */
    phte_store_le64(inb, db);
    phte_store_le64(inb + 16, da);
    for (i = 2; i + 1 < m; i += 2) {
        db = PH_ROLL2(c, db, qo[i - 1], qo[i], q[i - 1], q[i]);
        da = PH_ROLL2(c, da, qo[i], qo[i + 1], q[i], q[i + 1]);
        phte_store_le64(inb + i * 16, db);
        phte_store_le64(inb + (i + 1) * 16, da);
    }
    if (i < m) { /* odd m: one even-lane step left for position m-1 */
        db = PH_ROLL2(c, db, qo[i - 1], qo[i], q[i - 1], q[i]);
        phte_store_le64(inb + i * 16, db);
        *d_io = db;
    } else {
        *d_io = da;
    }
}

/* --- portable path: batched AES via OpenSSL EVP ------------------------ */

static int64_t PH_FN(scan_evp)(PH_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint8_t inb[PH_SB * 16];
    uint8_t outb[PH_SB * 16];
    uint64_t d = *digest;
    size_t base = 0;
    int outlen;

    memset(inb, 0, sizeof(inb)); /* bytes 8..15 of each block stay zero */
    while (base < n) {
        const uint8_t *q = p + base;
        size_t m = n - base;
        if (m > PH_SB)
            m = PH_SB;
        PH_FN(fill2)(c, q, q - 64, m, &d, inb);
        outlen = 0;
        if (!EVP_EncryptUpdate(c->base.evp, outb, &outlen, inb, (int)(m * 16)) || outlen != (int)(m * 16))
            return -2; /* OpenSSL failure; caller raises */
        for (size_t i = 0; i < m; i++) {
            if ((phte_load_le64(outb + i * 16) & mask) == 0) {
                /* The chunker does not use the digest at a cut (it warms up
                 * afresh for the next chunk), but keep the out-parameter
                 * exact like the hardware paths do: recomputing it costs one
                 * 64-byte warm-up per chunk, storing all digests would cost
                 * more. */
                *digest = PH_DIGEST64(c, q + i - 63);
                return (int64_t)(base + i);
            }
        }
        base += m;
    }
    *digest = d;
    return -1;
}

/* --- hardware paths ----------------------------------------------------
 *
 * The 128-bit hardware paths process groups of 8 positions (the VAES/AVX-512
 * path below uses the same structure with groups of 32): the two rolling
 * lanes advance 4 stride-2 steps each (two independent dependency chains),
 * then the 8 digests are encrypted with interleaved AES instructions, which
 * execute on different ports than the rolling work and thus overlap with the
 * next group's.
 *
 * Loop invariant: entering a group at position i, db = digest at i and
 * da = digest at i+1 (both already computed); the group emits digests for
 * i..i+7 and prepares db/da for i+8/i+9 (reading bytes up to q[i+9], hence
 * the i + 10 <= n loop bound). */

#if PHTE_HAVE_HW && defined(__aarch64__)

PHTE_HW_TARGET static int64_t
PH_FN(scan_hw)(PH_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint8x16_t k[11];
    uint64_t d = *digest, da, db;
    const uint8_t *qo = p - 64;
    size_t i = 0;
    int lanes_live = 0;

    for (int j = 0; j < 11; j++)
        k[j] = vld1q_u8(c->base.rk[j]);

    if (n >= 10) {
        db = PH_ROLL(c, d, qo[0], p[0]);               /* d_0 */
        da = PH_ROLL2(c, d, qo[0], qo[1], p[0], p[1]); /* d_1 */
        lanes_live = 1;
    }

    while (lanes_live && i + 10 <= n) {
        uint64_t dg[8];
        uint8x16_t b0, b1, b2, b3, b4, b5, b6, b7;

        dg[0] = db;
        dg[1] = da;
        db = PH_ROLL2(c, db, qo[i + 1], qo[i + 2], p[i + 1], p[i + 2]); dg[2] = db;
        da = PH_ROLL2(c, da, qo[i + 2], qo[i + 3], p[i + 2], p[i + 3]); dg[3] = da;
        db = PH_ROLL2(c, db, qo[i + 3], qo[i + 4], p[i + 3], p[i + 4]); dg[4] = db;
        da = PH_ROLL2(c, da, qo[i + 4], qo[i + 5], p[i + 4], p[i + 5]); dg[5] = da;
        db = PH_ROLL2(c, db, qo[i + 5], qo[i + 6], p[i + 5], p[i + 6]); dg[6] = db;
        da = PH_ROLL2(c, da, qo[i + 6], qo[i + 7], p[i + 6], p[i + 7]); dg[7] = da;
        /* prepare the next group's invariant (digests at i+8, i+9) */
        db = PH_ROLL2(c, db, qo[i + 7], qo[i + 8], p[i + 7], p[i + 8]);
        da = PH_ROLL2(c, da, qo[i + 8], qo[i + 9], p[i + 8], p[i + 9]);

        b0 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[0]), vcreate_u64(0)));
        b1 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[1]), vcreate_u64(0)));
        b2 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[2]), vcreate_u64(0)));
        b3 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[3]), vcreate_u64(0)));
        b4 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[4]), vcreate_u64(0)));
        b5 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[5]), vcreate_u64(0)));
        b6 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[6]), vcreate_u64(0)));
        b7 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[7]), vcreate_u64(0)));
        for (int r = 0; r < 9; r++) {
            b0 = vaesmcq_u8(vaeseq_u8(b0, k[r]));
            b1 = vaesmcq_u8(vaeseq_u8(b1, k[r]));
            b2 = vaesmcq_u8(vaeseq_u8(b2, k[r]));
            b3 = vaesmcq_u8(vaeseq_u8(b3, k[r]));
            b4 = vaesmcq_u8(vaeseq_u8(b4, k[r]));
            b5 = vaesmcq_u8(vaeseq_u8(b5, k[r]));
            b6 = vaesmcq_u8(vaeseq_u8(b6, k[r]));
            b7 = vaesmcq_u8(vaeseq_u8(b7, k[r]));
        }
        b0 = veorq_u8(vaeseq_u8(b0, k[9]), k[10]);
        b1 = veorq_u8(vaeseq_u8(b1, k[9]), k[10]);
        b2 = veorq_u8(vaeseq_u8(b2, k[9]), k[10]);
        b3 = veorq_u8(vaeseq_u8(b3, k[9]), k[10]);
        b4 = veorq_u8(vaeseq_u8(b4, k[9]), k[10]);
        b5 = veorq_u8(vaeseq_u8(b5, k[9]), k[10]);
        b6 = veorq_u8(vaeseq_u8(b6, k[9]), k[10]);
        b7 = veorq_u8(vaeseq_u8(b7, k[9]), k[10]);

        /* Test all 8 ciphertexts without leaving the vector domain: uzp1
         * packs the low halves (the cut-decision uint64) of two blocks into
         * one vector, then and/cmeq-zero/or-reduce. Moving the 8 values to
         * general registers instead - one fmov each, plus 8 scalar and/cmp
         * pairs - costs noticeably more on the common no-hit path, where
         * nothing but the single "any lane hit" bit is ever needed. */
        {
            const uint64x2_t maskv = vdupq_n_u64(mask);
            uint64x2_t h01 = vuzp1q_u64(vreinterpretq_u64_u8(b0), vreinterpretq_u64_u8(b1));
            uint64x2_t h23 = vuzp1q_u64(vreinterpretq_u64_u8(b2), vreinterpretq_u64_u8(b3));
            uint64x2_t h45 = vuzp1q_u64(vreinterpretq_u64_u8(b4), vreinterpretq_u64_u8(b5));
            uint64x2_t h67 = vuzp1q_u64(vreinterpretq_u64_u8(b6), vreinterpretq_u64_u8(b7));
            uint64x2_t any = vorrq_u64(vorrq_u64(vceqzq_u64(vandq_u64(h01, maskv)),
                                                vceqzq_u64(vandq_u64(h23, maskv))),
                                       vorrq_u64(vceqzq_u64(vandq_u64(h45, maskv)),
                                                vceqzq_u64(vandq_u64(h67, maskv))));
            if (vmaxvq_u32(vreinterpretq_u32_u64(any))) {
                uint64_t cs[8];
                vst1q_u64(cs + 0, h01);
                vst1q_u64(cs + 2, h23);
                vst1q_u64(cs + 4, h45);
                vst1q_u64(cs + 6, h67);
                for (int j = 0; j < 8; j++) {
                    if ((cs[j] & mask) == 0) {
                        *digest = dg[j];
                        return (int64_t)(i + j);
                    }
                }
            }
        }
        i += 8;
    }
    /* tail: single positions. If the lanes ran, db already is the digest at
     * position i; check it first, then continue with single-step rolls. */
    if (lanes_live && i < n) {
        uint8x16_t b = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(db), vcreate_u64(0)));
        b = phte_aes1_neon(k, b);
        if ((vgetq_lane_u64(vreinterpretq_u64_u8(b), 0) & mask) == 0) {
            *digest = db;
            return (int64_t)i;
        }
        d = db;
        i++;
    }
    while (i < n) {
        uint8x16_t b;
        d = PH_ROLL(c, d, qo[i], p[i]);
        b = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(d), vcreate_u64(0)));
        b = phte_aes1_neon(k, b);
        if ((vgetq_lane_u64(vreinterpretq_u64_u8(b), 0) & mask) == 0) {
            *digest = d;
            return (int64_t)i;
        }
        i++;
    }
    *digest = d;
    return -1;
}

#elif PHTE_HAVE_HW

/* apply one AES round (or the last one) to the 8 blocks in flight */
#define PH_R8(op, k) \
    b0 = op(b0, k); b1 = op(b1, k); b2 = op(b2, k); b3 = op(b3, k); \
    b4 = op(b4, k); b5 = op(b5, k); b6 = op(b6, k); b7 = op(b7, k)

/* The AES rounds and the 8-way test are spelled out rather than looped:
 * gcc at -O2 keeps such loops rolled (12 instructions per round, two
 * branches per tested position) and clang serialises the early-exit test
 * loop into 8 dependent chains; both cost about a fifth of the path's time
 * on a Zen 4. The test is branch-free in the vector domain: the 8 low
 * ciphertext qwords are packed pairwise (unpcklqdq), masked, compared to
 * zero (pcmpeqq, SSE4.1 - every CPU with AES-NI has it), or-reduced, and
 * only a hit enters the lane search. */
__attribute__((target("aes,sse4.1"))) static int64_t
PH_FN(scan_hw)(PH_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint64_t d = *digest, da, db;
    const uint8_t *qo = p - 64;
    size_t i = 0;
    int lanes_live = 0;
    const __m128i M = _mm_set1_epi64x((long long)mask), Z = _mm_setzero_si128();

    if (n >= 10) {
        db = PH_ROLL(c, d, qo[0], p[0]);               /* d_0 */
        da = PH_ROLL2(c, d, qo[0], qo[1], p[0], p[1]); /* d_1 */
        lanes_live = 1;
    }

    while (lanes_live && i + 10 <= n) {
        uint64_t dg[8];
        __m128i b0, b1, b2, b3, b4, b5, b6, b7, kr;

        dg[0] = db;
        dg[1] = da;
        db = PH_ROLL2(c, db, qo[i + 1], qo[i + 2], p[i + 1], p[i + 2]); dg[2] = db;
        da = PH_ROLL2(c, da, qo[i + 2], qo[i + 3], p[i + 2], p[i + 3]); dg[3] = da;
        db = PH_ROLL2(c, db, qo[i + 3], qo[i + 4], p[i + 3], p[i + 4]); dg[4] = db;
        da = PH_ROLL2(c, da, qo[i + 4], qo[i + 5], p[i + 4], p[i + 5]); dg[5] = da;
        db = PH_ROLL2(c, db, qo[i + 5], qo[i + 6], p[i + 5], p[i + 6]); dg[6] = db;
        da = PH_ROLL2(c, da, qo[i + 6], qo[i + 7], p[i + 6], p[i + 7]); dg[7] = da;
        db = PH_ROLL2(c, db, qo[i + 7], qo[i + 8], p[i + 7], p[i + 8]);
        da = PH_ROLL2(c, da, qo[i + 8], qo[i + 9], p[i + 8], p[i + 9]);

        /* 8 blocks in flight; round keys are re-loaded per round (they stay
         * hot in L1) to keep register pressure within the 16 XMM registers */
        kr = _mm_loadu_si128((const __m128i *)c->base.rk[0]);
        b0 = _mm_xor_si128(_mm_cvtsi64_si128((long long)dg[0]), kr);
        b1 = _mm_xor_si128(_mm_cvtsi64_si128((long long)dg[1]), kr);
        b2 = _mm_xor_si128(_mm_cvtsi64_si128((long long)dg[2]), kr);
        b3 = _mm_xor_si128(_mm_cvtsi64_si128((long long)dg[3]), kr);
        b4 = _mm_xor_si128(_mm_cvtsi64_si128((long long)dg[4]), kr);
        b5 = _mm_xor_si128(_mm_cvtsi64_si128((long long)dg[5]), kr);
        b6 = _mm_xor_si128(_mm_cvtsi64_si128((long long)dg[6]), kr);
        b7 = _mm_xor_si128(_mm_cvtsi64_si128((long long)dg[7]), kr);
#define PH_ROUND(r) \
        kr = _mm_loadu_si128((const __m128i *)c->base.rk[r]); \
        PH_R8(_mm_aesenc_si128, kr)
        PH_ROUND(1); PH_ROUND(2); PH_ROUND(3); PH_ROUND(4); PH_ROUND(5);
        PH_ROUND(6); PH_ROUND(7); PH_ROUND(8); PH_ROUND(9);
#undef PH_ROUND
        kr = _mm_loadu_si128((const __m128i *)c->base.rk[10]);
        PH_R8(_mm_aesenclast_si128, kr);

        {
            __m128i e01 = _mm_cmpeq_epi64(_mm_and_si128(_mm_unpacklo_epi64(b0, b1), M), Z);
            __m128i e23 = _mm_cmpeq_epi64(_mm_and_si128(_mm_unpacklo_epi64(b2, b3), M), Z);
            __m128i e45 = _mm_cmpeq_epi64(_mm_and_si128(_mm_unpacklo_epi64(b4, b5), M), Z);
            __m128i e67 = _mm_cmpeq_epi64(_mm_and_si128(_mm_unpacklo_epi64(b6, b7), M), Z);
            __m128i any = _mm_or_si128(_mm_or_si128(e01, e23), _mm_or_si128(e45, e67));
            if (_mm_movemask_epi8(any)) {
                /* bit j of hits = position i + j hit; the lowest one wins */
                unsigned hits = (unsigned)_mm_movemask_pd(_mm_castsi128_pd(e01)) |
                                ((unsigned)_mm_movemask_pd(_mm_castsi128_pd(e23)) << 2) |
                                ((unsigned)_mm_movemask_pd(_mm_castsi128_pd(e45)) << 4) |
                                ((unsigned)_mm_movemask_pd(_mm_castsi128_pd(e67)) << 6);
                int j = __builtin_ctz(hits);
                *digest = dg[j];
                return (int64_t)(i + (size_t)j);
            }
        }
        i += 8;
    }
    if (lanes_live && i < n) {
        __m128i b = phte_aes1_ni(c->base.rk, _mm_set_epi64x(0, (long long)db));
        if (((uint64_t)_mm_cvtsi128_si64(b) & mask) == 0) {
            *digest = db;
            return (int64_t)i;
        }
        d = db;
        i++;
    }
    while (i < n) {
        __m128i b;
        d = PH_ROLL(c, d, qo[i], p[i]);
        b = phte_aes1_ni(c->base.rk, _mm_set_epi64x(0, (long long)d));
        if (((uint64_t)_mm_cvtsi128_si64(b) & mask) == 0) {
            *digest = d;
            return (int64_t)i;
        }
        i++;
    }
    *digest = d;
    return -1;
}

#endif /* PHTE_HAVE_HW */

#if PHTE_HAVE_HW512

/* VAES/AVX-512 variant of the x86-64 hardware path: the same two rolling
 * lanes, but groups of 32 positions whose digests are encrypted as 8 zmm
 * vectors of 4 AES blocks each - 4x fewer AES instructions than the 128-bit
 * path, the round keys stay register-resident (32 zmm registers instead of
 * 16 xmm, so no per-round key reloads), and the 8 independent chains hide
 * the vaesenc latency (2 chains would be latency-bound), and a masked
 * vptestnmq tests the 4 ciphertext-low qwords against the mask without
 * extracting. Every digest is exact and every position is tested, so cut
 * points stay bit-identical to the other paths.
 *
 * The digests are stored pre-spread: an AES input block wants the digest in
 * the low qword and zero in the high one, so dgs[] keeps a digest in every
 * even slot and a zero in every odd one. The zeros are written once at entry
 * and never touched again, which makes each vector's input a plain aligned
 * 512-bit load. Packing the digests and spreading them with vpexpandq (eight
 * of those per group) instead costs the same stores and measurably more
 * time - about 9% of the whole toeplitz-aes scan, 6% of rabin-aes. */
__attribute__((target("aes,sse2,vaes,avx512f"))) static int64_t
PH_FN(scan_hw512)(PH_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    __m512i k[11];
    __m512i M = _mm512_set1_epi64((long long)mask);
    /* digest at dgs[2j], zero at dgs[2j+1] (= AES input block bytes 8..15) */
    uint64_t dgs[64] __attribute__((aligned(64)));
    uint64_t d = *digest, da, db;
    const uint8_t *qo = p - 64;
    size_t i = 0;
    int lanes_live = 0;

    /* broadcast each 128-bit round key to all four block lanes */
    for (int j = 0; j < 11; j++)
        k[j] = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)c->base.rk[j]));
    for (int j = 1; j < 64; j += 2)
        dgs[j] = 0;

    if (n >= 34) {
        db = PH_ROLL(c, d, qo[0], p[0]);               /* d_0 */
        da = PH_ROLL2(c, d, qo[0], qo[1], p[0], p[1]); /* d_1 */
        lanes_live = 1;
    }

    while (lanes_live && i + 34 <= n) {
        __m512i b0, b1, b2, b3, b4, b5, b6, b7;
        __mmask8 h0, h1, h2, h3, h4, h5, h6, h7;

        /* The 15 stride-2 roll steps and the 9 AES rounds are spelled out by
         * macro: gcc at -O2 keeps them as loops, which for the rounds means
         * 72 zmm register copies per group and for the rolls an index chain
         * (Zen 4, toeplitz-aes: 7.06 -> 6.40 cycles per byte unrolled). */
        dgs[0] = db;
        dgs[2] = da;
#define PH_STEP(j) \
        db = PH_ROLL2(c, db, qo[i + (j) - 1], qo[i + (j)], p[i + (j) - 1], p[i + (j)]); dgs[2 * (j)] = db; \
        da = PH_ROLL2(c, da, qo[i + (j)], qo[i + (j) + 1], p[i + (j)], p[i + (j) + 1]); dgs[2 * (j) + 2] = da
        PH_STEP(2); PH_STEP(4); PH_STEP(6); PH_STEP(8); PH_STEP(10); PH_STEP(12); PH_STEP(14); PH_STEP(16);
        PH_STEP(18); PH_STEP(20); PH_STEP(22); PH_STEP(24); PH_STEP(26); PH_STEP(28); PH_STEP(30);
#undef PH_STEP
        /* prepare the next group's invariant (digests at i+32, i+33) */
        db = PH_ROLL2(c, db, qo[i + 31], qo[i + 32], p[i + 31], p[i + 32]);
        da = PH_ROLL2(c, da, qo[i + 32], qo[i + 33], p[i + 32], p[i + 33]);

        /* each vector's 4 blocks are already laid out in dgs (digest in the
         * low qword of every block, zero in the high one) */
        b0 = _mm512_xor_si512(_mm512_load_si512((const void *)(dgs + 0)), k[0]);
        b1 = _mm512_xor_si512(_mm512_load_si512((const void *)(dgs + 8)), k[0]);
        b2 = _mm512_xor_si512(_mm512_load_si512((const void *)(dgs + 16)), k[0]);
        b3 = _mm512_xor_si512(_mm512_load_si512((const void *)(dgs + 24)), k[0]);
        b4 = _mm512_xor_si512(_mm512_load_si512((const void *)(dgs + 32)), k[0]);
        b5 = _mm512_xor_si512(_mm512_load_si512((const void *)(dgs + 40)), k[0]);
        b6 = _mm512_xor_si512(_mm512_load_si512((const void *)(dgs + 48)), k[0]);
        b7 = _mm512_xor_si512(_mm512_load_si512((const void *)(dgs + 56)), k[0]);
        PH_R8(_mm512_aesenc_epi128, k[1]); PH_R8(_mm512_aesenc_epi128, k[2]); PH_R8(_mm512_aesenc_epi128, k[3]);
        PH_R8(_mm512_aesenc_epi128, k[4]); PH_R8(_mm512_aesenc_epi128, k[5]); PH_R8(_mm512_aesenc_epi128, k[6]);
        PH_R8(_mm512_aesenc_epi128, k[7]); PH_R8(_mm512_aesenc_epi128, k[8]); PH_R8(_mm512_aesenc_epi128, k[9]);
        h0 = _mm512_mask_testn_epi64_mask(0x55, _mm512_aesenclast_epi128(b0, k[10]), M);
        h1 = _mm512_mask_testn_epi64_mask(0x55, _mm512_aesenclast_epi128(b1, k[10]), M);
        h2 = _mm512_mask_testn_epi64_mask(0x55, _mm512_aesenclast_epi128(b2, k[10]), M);
        h3 = _mm512_mask_testn_epi64_mask(0x55, _mm512_aesenclast_epi128(b3, k[10]), M);
        h4 = _mm512_mask_testn_epi64_mask(0x55, _mm512_aesenclast_epi128(b4, k[10]), M);
        h5 = _mm512_mask_testn_epi64_mask(0x55, _mm512_aesenclast_epi128(b5, k[10]), M);
        h6 = _mm512_mask_testn_epi64_mask(0x55, _mm512_aesenclast_epi128(b6, k[10]), M);
        h7 = _mm512_mask_testn_epi64_mask(0x55, _mm512_aesenclast_epi128(b7, k[10]), M);

        if (h0 | h1 | h2 | h3 | h4 | h5 | h6 | h7) {
            /* block j of vector g is qword lane 2j and position i + 4g + j */
            const uint8_t hs[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
            for (int j = 0; j < 32; j++) {
                if ((hs[j >> 2] >> ((j & 3) * 2)) & 1) {
                    *digest = dgs[2 * j];
                    return (int64_t)(i + j);
                }
            }
        }
        i += 32;
    }
    /* tail: single positions, exactly as in the 128-bit path */
    if (lanes_live && i < n) {
        __m128i b = phte_aes1_ni(c->base.rk, _mm_set_epi64x(0, (long long)db));
        if (((uint64_t)_mm_cvtsi128_si64(b) & mask) == 0) {
            *digest = db;
            return (int64_t)i;
        }
        d = db;
        i++;
    }
    while (i < n) {
        __m128i b;
        d = PH_ROLL(c, d, qo[i], p[i]);
        b = phte_aes1_ni(c->base.rk, _mm_set_epi64x(0, (long long)d));
        if (((uint64_t)_mm_cvtsi128_si64(b) & mask) == 0) {
            *digest = d;
            return (int64_t)i;
        }
        i++;
    }
    *digest = d;
    return -1;
}

#endif /* PHTE_HAVE_HW512 */

/* --- dispatch (exported) ------------------------------------------------ */

int64_t PH_FN(scan)(PH_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
#if PHTE_HAVE_HW512
    if (c->base.use_hw512)
        return PH_FN(scan_hw512)(c, p, n, digest, mask);
#endif
#if PHTE_HAVE_HW
    if (c->base.use_hw)
        return PH_FN(scan_hw)(c, p, n, digest, mask);
#endif
    return PH_FN(scan_evp)(c, p, n, digest, mask);
}

const char *PH_FN(kind)(const PH_CTX *c)
{
    return phte_base_kind(&c->base);
}

void PH_FN(free)(PH_CTX *c)
{
    if (c != NULL) {
        phte_base_free(&c->base);
        free(c);
    }
}
