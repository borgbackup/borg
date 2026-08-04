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

/* the shared scan template: defines gl_scan, gl_kind and gl_free */
#define PH_PREFIX gl_
#define PH_CTX GL_CTX
#define PH_ROLL gl_roll
#define PH_ROLL2 gl_roll2
#define PH_DIGEST64 gl_digest64
#include "phte_scan.h"

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
    if (!phte_base_init(&c->base, aes_key, force_sw)) {
        free(c);
        return NULL;
    }
    return c;
}
