/* goldilocks-aes chunker scan kernel, see goldilocks_aes_impl.h and
 * goldilocks_aes.pyx.
 *
 * Only the rolling polynomial hash over the Goldilocks prime field lives
 * here; the AES layer, the two-lane scan structure and the context plumbing
 * are shared with the other UHF-then-PRF chunkers (phte_core.h,
 * phte_scan.h). */

#include <stdlib.h>
#include <string.h>

#include "phte_core.h"
#include "goldilocks_aes_impl.h"

#define GL_P 0xFFFFFFFF00000001ULL /* the Goldilocks prime 2^64 - 2^32 + 1 */
#define GL_EPS 0xFFFFFFFFULL       /* 2^64 mod p = 2^32 - 1 */

struct GL_CTX {
    PHTE_BASE base;
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
};

/* --- 64x64 -> 128 bit widening multiply ---------------------------------
 *
 * The field multiply needs the full 128-bit product. GCC and clang offer
 * __uint128_t for that, but only on 64-bit targets - on 32-bit ones (armhf,
 * i386, ...) the type does not exist and using it is a hard compile error,
 * so there a portable fallback built from four 32x32 -> 64 multiplies is
 * used instead. Both compute the same product, so this chunker's cut points
 * are identical on all architectures; the fallback is just slower.
 *
 * Defining BORG_GL_NO_INT128 forces the fallback also where __uint128_t
 * exists, so the 32-bit path can be tested on a 64-bit machine. */
#if defined(__SIZEOF_INT128__) && !defined(BORG_GL_NO_INT128)

static inline void gl_mul_wide(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi)
{
    __uint128_t t = (__uint128_t)a * b;
    *lo = (uint64_t)t;
    *hi = (uint64_t)(t >> 64);
}

#else

static inline void gl_mul_wide(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi)
{
    uint64_t a0 = (uint32_t)a, a1 = a >> 32;
    uint64_t b0 = (uint32_t)b, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    /* the cross terms carry into the top half; neither sum can overflow */
    uint64_t mid = p10 + (p00 >> 32) + (uint32_t)p01;
    *lo = (mid << 32) | (uint32_t)p00;
    *hi = p11 + (mid >> 32) + (p01 >> 32);
}

#endif

/* --- Goldilocks field arithmetic ---------------------------------------
 *
 * Every digest the scan produces is canonical (< p): it is fed to AES
 * verbatim, so a non-canonical representation of the same field element
 * would change cut decisions. The rolls reach that via gl_add, which always
 * canonicalizes; only the multiply inside them is allowed to hand on a
 * merely reduced (< 2^64) representative, see gl_mul_lazy. */

/* The reductions are data-dependent and unpredictable (~27% branch-miss rate
 * measured), so they must not become branches. Writing them as if() or as a
 * ternary lets GCC emit real conditional jumps - the mispredicts alone cost
 * more than the arithmetic (gl_mul: 15.1 vs 4.4 cycles per call). The
 * __builtin_*_overflow forms keep the carry/borrow in the flags, so the
 * compiler settles on sbb/adc + mask instead. Results are unchanged: the
 * value is still fully canonical, which matters because it is fed to AES. */
static inline uint64_t gl_add(uint64_t a, uint64_t b)
{
    uint64_t s, u;
    unsigned char carry = __builtin_add_overflow(a, b, &s);
    s += ((uint64_t)0 - (uint64_t)carry) & GL_EPS; /* 2^64 mod p; cannot re-carry */
    return __builtin_sub_overflow(s, GL_P, &u) ? s : u;
}

/* a * b mod p via the standard 2^64 = 2^32 - 1 folding (risc0/plonky2 style):
 * with the 128-bit product split as lo + hi*2^64 and hi = hi_hi*2^32 + hi_lo,
 * 2^64 = eps and 2^96 = -1 (mod p) give lo - hi_hi + hi_lo*eps. */
static inline uint64_t gl_mul(uint64_t a, uint64_t b)
{
    uint64_t lo, hi;
    gl_mul_wide(a, b, &lo, &hi);
    uint64_t hi_hi = hi >> 32, hi_lo = hi & GL_EPS;
    uint64_t t0, r, u;
    unsigned char borrow = __builtin_sub_overflow(lo, hi_hi, &t0);
    t0 -= ((uint64_t)0 - (uint64_t)borrow) & GL_EPS; /* -2^64 = -eps (mod p) */
    /* t1 = hi_lo * eps < 2^64 - 2^33 + 2, no overflow */
    unsigned char carry = __builtin_add_overflow(t0, hi_lo * GL_EPS, &r);
    r += ((uint64_t)0 - (uint64_t)carry) & GL_EPS; /* cannot re-carry */
    return __builtin_sub_overflow(r, GL_P, &u) ? r : u;
}

/* gl_mul without the final canonicalization: the result is congruent to a*b
 * mod p but only bounded by 2^64, not by p.
 *
 * That is enough for the rolls, because both feed it straight into a gl_add
 * whose other operand is canonical, and that gl_add canonicalizes anyway.
 * The bound still holds with a non-canonical first operand: for a < 2^64 and
 * b < p, a carry leaves a + b - 2^64 <= p - 2, so adding eps cannot carry a
 * second time, and the one conditional subtraction of p then lands below p
 * (r - p < 2^32). So the digest handed to AES stays canonical - which it must
 * be, since it is fed to AES verbatim - while the multiply chain that limits
 * this kernel loses its trailing compare and select. */
static inline uint64_t gl_mul_lazy(uint64_t a, uint64_t b)
{
    uint64_t lo, hi;
    gl_mul_wide(a, b, &lo, &hi);
    uint64_t hi_hi = hi >> 32, hi_lo = hi & GL_EPS;
    uint64_t t0, r;
    unsigned char borrow = __builtin_sub_overflow(lo, hi_hi, &t0);
    t0 -= ((uint64_t)0 - (uint64_t)borrow) & GL_EPS; /* -2^64 = -eps (mod p) */
    unsigned char carry = __builtin_add_overflow(t0, hi_lo * GL_EPS, &r);
    r += ((uint64_t)0 - (uint64_t)carry) & GL_EPS; /* cannot re-carry */
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
    return gl_add(gl_mul_lazy(s, c->k1), delta);
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
    return gl_add(gl_mul_lazy(s, c->k2), delta);
}

uint64_t gl_digest64(const GL_CTX *c, const uint8_t *q)
{
    uint64_t d = 0;
    for (int j = 0; j < 64; j++)
        d = gl_add(gl_mul(d, c->k1), q[j]);
    return d;
}

/* the shared scan template: defines gl_scan, gl_kind and gl_free */
#define PH_PREFIX gl_
#define PH_CTX GL_CTX
#define PH_ROLL gl_roll
#define PH_ROLL2 gl_roll2
#define PH_DIGEST64 gl_digest64
#include "phte_scan.h"

GL_CTX *gl_new(const uint64_t tables[GL_TABLES * 256], uint64_t k1, uint64_t k2,
               const uint8_t aes_key[16], int kernel)
{
    GL_CTX *c = calloc(1, sizeof(GL_CTX));
    if (c == NULL)
        return NULL;
    memcpy(c->nout64_tbl, tables + 0 * 256, sizeof(c->nout64_tbl));
    memcpy(c->nout65_tbl, tables + 1 * 256, sizeof(c->nout65_tbl));
    memcpy(c->in1_tbl, tables + 2 * 256, sizeof(c->in1_tbl));
    c->k1 = k1;
    c->k2 = k2;
    if (!phte_base_init(&c->base, aes_key, kernel)) {
        free(c);
        return NULL;
    }
    return c;
}
