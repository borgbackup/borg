/* goldilocks-aes chunker scan kernel, see goldilocks_aes_impl.h and
 * goldilocks_aes.pyx. Mirrors rabin_aes_impl.c; only the rolling arithmetic
 * differs (Goldilocks prime field instead of GF(2)[x] mod P). */

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "goldilocks_aes_impl.h"

#define GL_P 0xFFFFFFFF00000001ULL /* the Goldilocks prime 2^64 - 2^32 + 1 */
#define GL_EPS 0xFFFFFFFFULL       /* 2^64 mod p = 2^32 - 1 */

struct GL_CTX {
    /* rolling tables; all entries are canonical field elements (< p).
     * The single-step table defines the state update; the stride-2 tables are
     * algebraically derived from it (see gl_roll2) and exist only so that
     * two independent "lanes" (even/odd positions) can advance with stride 2,
     * halving the multiply latency chain that limits single-step rolling. */
    uint64_t nout64_tbl[256]; /* (-b * K^64) mod p (removal of the leaving byte) */
    uint64_t nout65_tbl[256]; /* (-b * K^65) mod p (stride-2 removal, older byte) */
    uint64_t in1_tbl[256];    /* ( b * K   ) mod p (stride-2, older incoming byte) */
    uint64_t k1;              /* K   (single-step state multiplier) */
    uint64_t k2;              /* K^2 (stride-2 state multiplier) */
    uint8_t rk[11][16];       /* AES-128 round keys, for the hardware paths */
    EVP_CIPHER_CTX *evp;
    int use_hw;
};

/* --- portable helpers ------------------------------------------------- */

static inline void store_le64(uint8_t *b, uint64_t v)
{
    for (int j = 0; j < 8; j++)
        b[j] = (uint8_t)(v >> (8 * j));
}

static inline uint64_t load_le64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int j = 0; j < 8; j++)
        v |= ((uint64_t)b[j]) << (8 * j);
    return v;
}

/* --- Goldilocks field arithmetic ---------------------------------------
 *
 * All values are kept canonical (< p) at every step: the state is fed to
 * AES verbatim, so a non-canonical representation of the same field element
 * would change cut decisions. */

static inline uint64_t gl_add(uint64_t a, uint64_t b)
{
    uint64_t s = a + b;
    if (s < a)          /* carry out: 2^64 mod p = GL_EPS; cannot re-carry */
        s += GL_EPS;
    if (s >= GL_P)
        s -= GL_P;
    return s;
}

/* a * b mod p via the standard 2^64 = 2^32 - 1 folding (risc0/plonky2 style):
 * with the 128-bit product split as lo + hi*2^64 and hi = hi_hi*2^32 + hi_lo,
 * 2^64 = eps and 2^96 = -1 (mod p) give lo - hi_hi + hi_lo*eps. */
static inline uint64_t gl_mul(uint64_t a, uint64_t b)
{
    __uint128_t t = (__uint128_t)a * b;
    uint64_t lo = (uint64_t)t, hi = (uint64_t)(t >> 64);
    uint64_t hi_hi = hi >> 32, hi_lo = hi & GL_EPS;
    uint64_t t0 = lo - hi_hi;
    if (lo < hi_hi)     /* borrow: -2^64 = -eps (mod p) */
        t0 -= GL_EPS;
    uint64_t t1 = hi_lo * GL_EPS; /* < 2^64 - 2^33 + 2, no overflow */
    uint64_t r = t0 + t1;
    if (r < t1)         /* carry out; cannot re-carry (t1 <= 2^64 - 2^33 + 1) */
        r += GL_EPS;
    if (r >= GL_P)
        r -= GL_P;
    return r;
}

/* Advance the state by one byte. The state is the window's polynomial hash
 * s = sum b_j * K^(63-j) (oldest byte at K^63, newest at K^0), so
 *   s' = s*K - byte_out*K^64 + byte_in.
 * The removal term comes negated from nout64_tbl, making the delta a pure
 * sum computed off the critical path; the s*K multiply is the serial chain. */
static inline uint64_t gl_roll(const GL_CTX *c, uint64_t s, uint8_t byte_out, uint8_t byte_in)
{
    uint64_t delta = gl_add(c->nout64_tbl[byte_out], byte_in);
    return gl_add(gl_mul(s, c->k1), delta);
}

/* Advance the state by TWO bytes in one step (exact composition of two
 * gl_roll steps, expanded using linearity over GF(p)):
 *   s' = s*K^2 - o0*K^65 - o1*K^64 + i0*K + i1   (mod p)
 * where (o0, i0) belong to the first composed step and (o1, i1) to the second.
 * Used to run two independent even/odd lanes; identical results to gl_roll
 * twice (canonical field elements are unique, so "identical" is exact). */
static inline uint64_t gl_roll2(const GL_CTX *c, uint64_t s,
                                uint8_t o0, uint8_t o1, uint8_t i0, uint8_t i1)
{
    uint64_t delta = gl_add(gl_add(c->nout65_tbl[o0], c->nout64_tbl[o1]),
                            gl_add(c->in1_tbl[i0], i1));
    return gl_add(gl_mul(s, c->k2), delta);
}

uint64_t gl_digest64(const GL_CTX *c, const uint8_t *q)
{
    uint64_t d = 0;
    for (int j = 0; j < 64; j++)
        d = gl_add(gl_mul(d, c->k1), q[j]);
    return d;
}

/* --- AES-128 key expansion (encryption-only, standard FIPS-197) -------- */

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static void aes128_expand(const uint8_t key[16], uint8_t rk[11][16])
{
    uint8_t rcon = 1;
    memcpy(rk[0], key, 16);
    for (int i = 1; i <= 10; i++) {
        rk[i][0] = (uint8_t)(rk[i - 1][0] ^ sbox[rk[i - 1][13]] ^ rcon);
        rk[i][1] = (uint8_t)(rk[i - 1][1] ^ sbox[rk[i - 1][14]]);
        rk[i][2] = (uint8_t)(rk[i - 1][2] ^ sbox[rk[i - 1][15]]);
        rk[i][3] = (uint8_t)(rk[i - 1][3] ^ sbox[rk[i - 1][12]]);
        for (int j = 4; j < 16; j++)
            rk[i][j] = (uint8_t)(rk[i - 1][j] ^ rk[i][j - 4]);
        rcon = (uint8_t)((rcon << 1) ^ ((rcon >> 7) * 0x1b));
    }
}

/* --- two-lane digest fill (shared by the portable path) ----------------- */

/* Compute the states for positions [0, m), writing each as an AES input
 * block (state LE in bytes 0..7; bytes 8..15 must already be zero) into inb.
 * On entry *d_io is the state at position -1; on return, at position m-1.
 * Uses two independent even/odd lanes advancing with stride 2 so the two
 * dependency chains overlap; identical to m single gl_roll steps. */
static inline void gl_fill2(const GL_CTX *c, const uint8_t *q, const uint8_t *qo,
                            size_t m, uint64_t *d_io, uint8_t *inb)
{
    uint64_t d = *d_io, da, db;
    size_t i;

    if (m == 1) {
        d = gl_roll(c, d, qo[0], q[0]);
        store_le64(inb, d);
        *d_io = d;
        return;
    }
    db = gl_roll(c, d, qo[0], q[0]);                /* even lane: d_0 */
    da = gl_roll2(c, d, qo[0], qo[1], q[0], q[1]);  /* odd lane:  d_1 */
    store_le64(inb, db);
    store_le64(inb + 16, da);
    for (i = 2; i + 1 < m; i += 2) {
        db = gl_roll2(c, db, qo[i - 1], qo[i], q[i - 1], q[i]);
        da = gl_roll2(c, da, qo[i], qo[i + 1], q[i], q[i + 1]);
        store_le64(inb + i * 16, db);
        store_le64(inb + (i + 1) * 16, da);
    }
    if (i < m) { /* odd m: one even-lane step left for position m-1 */
        db = gl_roll2(c, db, qo[i - 1], qo[i], q[i - 1], q[i]);
        store_le64(inb + i * 16, db);
        *d_io = db;
    } else {
        *d_io = da;
    }
}

/* --- portable path: batched AES via OpenSSL EVP ------------------------ */

/* sub-batch size (blocks); 512 * 16 B = 8 KiB in/out buffers on the stack */
#define GL_SB 512

static int64_t gl_scan_evp(GL_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint8_t inb[GL_SB * 16];
    uint8_t outb[GL_SB * 16];
    uint64_t d = *digest;
    size_t base = 0;
    int outlen;

    memset(inb, 0, sizeof(inb)); /* bytes 8..15 of each block stay zero */
    while (base < n) {
        const uint8_t *q = p + base;
        size_t m = n - base;
        if (m > GL_SB)
            m = GL_SB;
        gl_fill2(c, q, q - 64, m, &d, inb);
        outlen = 0;
        if (!EVP_EncryptUpdate(c->evp, outb, &outlen, inb, (int)(m * 16)) || outlen != (int)(m * 16))
            return -2; /* OpenSSL failure; caller raises */
        for (size_t i = 0; i < m; i++) {
            if ((load_le64(outb + i * 16) & mask) == 0) {
                /* recompute the state at the cut position (cheaper than
                 * storing all states: one 64-byte warm-up per chunk) */
                *digest = gl_digest64(c, q + i - 63);
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
 * Both hardware paths process groups of 8 positions: the two rolling lanes
 * advance 4 stride-2 steps each (two independent multiply chains), then the
 * 8 states are encrypted with interleaved AES instructions, which execute
 * on different ports than the integer multiplies and thus overlap with the
 * next group's rolling work.
 *
 * Loop invariant: entering a group at position i, db = state at i and
 * da = state at i+1 (both already computed); the group emits states for
 * i..i+7 and prepares db/da for i+8/i+9 (reading bytes up to q[i+9], hence
 * the i + 10 <= n loop bound). */

#if defined(__aarch64__) && defined(__ARM_FEATURE_AES)
#define GL_HAVE_HW 1
#define GL_KIND_HW "aes-arm64"

#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#endif

static int gl_hw_available(void)
{
#if defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
    return 1; /* compiler targeted +aes; on Apple Silicon it is always there */
#endif
}

static inline uint8x16_t gl_aes1_neon(const uint8x16_t k[11], uint8x16_t b)
{
    for (int r = 0; r < 9; r++)
        b = vaesmcq_u8(vaeseq_u8(b, k[r]));
    return veorq_u8(vaeseq_u8(b, k[9]), k[10]);
}

static int64_t gl_scan_hw(GL_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint8x16_t k[11];
    uint64_t d = *digest, da, db;
    const uint8_t *qo = p - 64;
    size_t i = 0;
    int lanes_live = 0;

    for (int j = 0; j < 11; j++)
        k[j] = vld1q_u8(c->rk[j]);

    if (n >= 10) {
        db = gl_roll(c, d, qo[0], p[0]);               /* d_0 */
        da = gl_roll2(c, d, qo[0], qo[1], p[0], p[1]); /* d_1 */
        lanes_live = 1;
    }

    while (lanes_live && i + 10 <= n) {
        uint64_t dg[8];
        uint8x16_t b0, b1, b2, b3, b4, b5, b6, b7;

        dg[0] = db;
        dg[1] = da;
        db = gl_roll2(c, db, qo[i + 1], qo[i + 2], p[i + 1], p[i + 2]); dg[2] = db;
        da = gl_roll2(c, da, qo[i + 2], qo[i + 3], p[i + 2], p[i + 3]); dg[3] = da;
        db = gl_roll2(c, db, qo[i + 3], qo[i + 4], p[i + 3], p[i + 4]); dg[4] = db;
        da = gl_roll2(c, da, qo[i + 4], qo[i + 5], p[i + 4], p[i + 5]); dg[5] = da;
        db = gl_roll2(c, db, qo[i + 5], qo[i + 6], p[i + 5], p[i + 6]); dg[6] = db;
        da = gl_roll2(c, da, qo[i + 6], qo[i + 7], p[i + 6], p[i + 7]); dg[7] = da;
        /* prepare the next group's invariant (states at i+8, i+9) */
        db = gl_roll2(c, db, qo[i + 7], qo[i + 8], p[i + 7], p[i + 8]);
        da = gl_roll2(c, da, qo[i + 8], qo[i + 9], p[i + 8], p[i + 9]);

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

        {
            uint64_t c0 = vgetq_lane_u64(vreinterpretq_u64_u8(b0), 0);
            uint64_t c1 = vgetq_lane_u64(vreinterpretq_u64_u8(b1), 0);
            uint64_t c2 = vgetq_lane_u64(vreinterpretq_u64_u8(b2), 0);
            uint64_t c3 = vgetq_lane_u64(vreinterpretq_u64_u8(b3), 0);
            uint64_t c4 = vgetq_lane_u64(vreinterpretq_u64_u8(b4), 0);
            uint64_t c5 = vgetq_lane_u64(vreinterpretq_u64_u8(b5), 0);
            uint64_t c6 = vgetq_lane_u64(vreinterpretq_u64_u8(b6), 0);
            uint64_t c7 = vgetq_lane_u64(vreinterpretq_u64_u8(b7), 0);
            if ((((c0 & mask) == 0) | ((c1 & mask) == 0) | ((c2 & mask) == 0) | ((c3 & mask) == 0) |
                 ((c4 & mask) == 0) | ((c5 & mask) == 0) | ((c6 & mask) == 0) | ((c7 & mask) == 0))) {
                uint64_t cs[8] = {c0, c1, c2, c3, c4, c5, c6, c7};
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
    /* tail: single positions. If the lanes ran, db already is the state at
     * position i; check it first, then continue with single-step rolls. */
    if (lanes_live && i < n) {
        uint8x16_t b = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(db), vcreate_u64(0)));
        b = gl_aes1_neon(k, b);
        if ((vgetq_lane_u64(vreinterpretq_u64_u8(b), 0) & mask) == 0) {
            *digest = db;
            return (int64_t)i;
        }
        d = db;
        i++;
    }
    while (i < n) {
        uint8x16_t b;
        d = gl_roll(c, d, qo[i], p[i]);
        b = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(d), vcreate_u64(0)));
        b = gl_aes1_neon(k, b);
        if ((vgetq_lane_u64(vreinterpretq_u64_u8(b), 0) & mask) == 0) {
            *digest = d;
            return (int64_t)i;
        }
        i++;
    }
    *digest = d;
    return -1;
}

#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#define GL_HAVE_HW 1
#define GL_KIND_HW "aes-ni"

#include <immintrin.h>

static int gl_hw_available(void)
{
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse2");
}

__attribute__((target("aes,sse2"))) static inline __m128i
gl_aes1_ni(const uint8_t rk[11][16], __m128i b)
{
    b = _mm_xor_si128(b, _mm_loadu_si128((const __m128i *)rk[0]));
    for (int r = 1; r < 10; r++)
        b = _mm_aesenc_si128(b, _mm_loadu_si128((const __m128i *)rk[r]));
    return _mm_aesenclast_si128(b, _mm_loadu_si128((const __m128i *)rk[10]));
}

__attribute__((target("aes,sse2"))) static int64_t
gl_scan_hw(GL_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint64_t d = *digest, da, db;
    const uint8_t *qo = p - 64;
    size_t i = 0;
    int lanes_live = 0;

    if (n >= 10) {
        db = gl_roll(c, d, qo[0], p[0]);               /* d_0 */
        da = gl_roll2(c, d, qo[0], qo[1], p[0], p[1]); /* d_1 */
        lanes_live = 1;
    }

    while (lanes_live && i + 10 <= n) {
        uint64_t dg[8];
        __m128i b0, b1, b2, b3, b4, b5, b6, b7, kr;

        dg[0] = db;
        dg[1] = da;
        db = gl_roll2(c, db, qo[i + 1], qo[i + 2], p[i + 1], p[i + 2]); dg[2] = db;
        da = gl_roll2(c, da, qo[i + 2], qo[i + 3], p[i + 2], p[i + 3]); dg[3] = da;
        db = gl_roll2(c, db, qo[i + 3], qo[i + 4], p[i + 3], p[i + 4]); dg[4] = db;
        da = gl_roll2(c, da, qo[i + 4], qo[i + 5], p[i + 4], p[i + 5]); dg[5] = da;
        db = gl_roll2(c, db, qo[i + 5], qo[i + 6], p[i + 5], p[i + 6]); dg[6] = db;
        da = gl_roll2(c, da, qo[i + 6], qo[i + 7], p[i + 6], p[i + 7]); dg[7] = da;
        db = gl_roll2(c, db, qo[i + 7], qo[i + 8], p[i + 7], p[i + 8]);
        da = gl_roll2(c, da, qo[i + 8], qo[i + 9], p[i + 8], p[i + 9]);

        /* 8 blocks in flight; round keys are re-loaded per round (they stay
         * hot in L1) to keep register pressure within the 16 XMM registers */
        kr = _mm_loadu_si128((const __m128i *)c->rk[0]);
        b0 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[0]), kr);
        b1 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[1]), kr);
        b2 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[2]), kr);
        b3 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[3]), kr);
        b4 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[4]), kr);
        b5 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[5]), kr);
        b6 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[6]), kr);
        b7 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[7]), kr);
        for (int r = 1; r < 10; r++) {
            kr = _mm_loadu_si128((const __m128i *)c->rk[r]);
            b0 = _mm_aesenc_si128(b0, kr);
            b1 = _mm_aesenc_si128(b1, kr);
            b2 = _mm_aesenc_si128(b2, kr);
            b3 = _mm_aesenc_si128(b3, kr);
            b4 = _mm_aesenc_si128(b4, kr);
            b5 = _mm_aesenc_si128(b5, kr);
            b6 = _mm_aesenc_si128(b6, kr);
            b7 = _mm_aesenc_si128(b7, kr);
        }
        kr = _mm_loadu_si128((const __m128i *)c->rk[10]);
        b0 = _mm_aesenclast_si128(b0, kr);
        b1 = _mm_aesenclast_si128(b1, kr);
        b2 = _mm_aesenclast_si128(b2, kr);
        b3 = _mm_aesenclast_si128(b3, kr);
        b4 = _mm_aesenclast_si128(b4, kr);
        b5 = _mm_aesenclast_si128(b5, kr);
        b6 = _mm_aesenclast_si128(b6, kr);
        b7 = _mm_aesenclast_si128(b7, kr);

        {
            uint64_t cs[8];
            cs[0] = (uint64_t)_mm_cvtsi128_si64(b0);
            cs[1] = (uint64_t)_mm_cvtsi128_si64(b1);
            cs[2] = (uint64_t)_mm_cvtsi128_si64(b2);
            cs[3] = (uint64_t)_mm_cvtsi128_si64(b3);
            cs[4] = (uint64_t)_mm_cvtsi128_si64(b4);
            cs[5] = (uint64_t)_mm_cvtsi128_si64(b5);
            cs[6] = (uint64_t)_mm_cvtsi128_si64(b6);
            cs[7] = (uint64_t)_mm_cvtsi128_si64(b7);
            for (int j = 0; j < 8; j++) {
                if ((cs[j] & mask) == 0) {
                    *digest = dg[j];
                    return (int64_t)(i + j);
                }
            }
        }
        i += 8;
    }
    if (lanes_live && i < n) {
        __m128i b = gl_aes1_ni(c->rk, _mm_set_epi64x(0, (long long)db));
        if (((uint64_t)_mm_cvtsi128_si64(b) & mask) == 0) {
            *digest = db;
            return (int64_t)i;
        }
        d = db;
        i++;
    }
    while (i < n) {
        __m128i b;
        d = gl_roll(c, d, qo[i], p[i]);
        b = gl_aes1_ni(c->rk, _mm_set_epi64x(0, (long long)d));
        if (((uint64_t)_mm_cvtsi128_si64(b) & mask) == 0) {
            *digest = d;
            return (int64_t)i;
        }
        i++;
    }
    *digest = d;
    return -1;
}

#else
#define GL_HAVE_HW 0
#endif

/* --- context management and dispatch ----------------------------------- */

GL_CTX *gl_new(const uint64_t tables[GL_TABLES * 256], uint64_t k1, uint64_t k2,
               const uint8_t aes_key[16], int force_sw)
{
    GL_CTX *c = calloc(1, sizeof(GL_CTX));
    if (c == NULL)
        return NULL;
    memcpy(c->nout64_tbl, tables + 0 * 256, sizeof(c->nout64_tbl));
    memcpy(c->nout65_tbl, tables + 1 * 256, sizeof(c->nout65_tbl));
    memcpy(c->in1_tbl, tables + 2 * 256, sizeof(c->in1_tbl));
    c->k1 = k1;
    c->k2 = k2;
    aes128_expand(aes_key, c->rk);
#if GL_HAVE_HW
    c->use_hw = !force_sw && gl_hw_available();
#else
    (void)force_sw;
    c->use_hw = 0;
#endif
    c->evp = EVP_CIPHER_CTX_new();
    if (c->evp == NULL) {
        free(c);
        return NULL;
    }
    if (!EVP_EncryptInit_ex(c->evp, EVP_aes_128_ecb(), NULL, aes_key, NULL) ||
        !EVP_CIPHER_CTX_set_padding(c->evp, 0)) {
        EVP_CIPHER_CTX_free(c->evp);
        free(c);
        return NULL;
    }
    return c;
}

void gl_free(GL_CTX *c)
{
    if (c != NULL) {
        if (c->evp != NULL)
            EVP_CIPHER_CTX_free(c->evp);
        free(c);
    }
}

const char *gl_kind(const GL_CTX *c)
{
#if GL_HAVE_HW
    if (c->use_hw)
        return GL_KIND_HW;
#endif
    (void)c;
    return "evp";
}

int64_t gl_scan(GL_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
#if GL_HAVE_HW
    if (c->use_hw)
        return gl_scan_hw(c, p, n, digest, mask);
#endif
    return gl_scan_evp(c, p, n, digest, mask);
}
