/* goldilocks-aes chunker scan kernel: rolling polynomial hash over the
 * Goldilocks prime field (UHF) + AES-128 (PRF).
 *
 * See goldilocks_aes.pyx for the scheme description. This C layer only
 * implements the performance-critical inner scan: roll the polynomial-hash
 * state one byte at a time, encrypt each state with AES-128, and cut where
 * the ciphertext's low bits (little-endian uint64 of the first 8 ciphertext
 * bytes) are all zero under mask.
 *
 * Structure is identical to rabin_aes_impl.c (two even/odd rolling lanes,
 * groups of 8 pipelined AES blocks on the hardware paths, batched OpenSSL
 * EVP on the portable path); only the rolling arithmetic differs: instead of
 * GF(2)[x] mod a secret P, the state is a polynomial hash over GF(p) with
 * p = 2^64 - 2^32 + 1 (the "Goldilocks" prime) and a secret evaluation
 * point K, as in the reference construction of eprint 2025/558.
 */

#ifndef BORG_GOLDILOCKS_AES_IMPL_H
#define BORG_GOLDILOCKS_AES_IMPL_H

#include <stdint.h>
#include <stddef.h>

#include "phte_kernel.h"

typedef struct GL_CTX GL_CTX;

/* Number of 256-entry rolling tables passed to gl_new, in this order:
 * [0] nout64_tbl: (-b * K^64) mod p (removal of the leaving byte; used by
 *                                    both the single-step and stride-2 rolls)
 * [1] nout65_tbl: (-b * K^65) mod p (stride-2 removal, older leaving byte)
 * [2] in1_tbl:    ( b * K   ) mod p (stride-2, older incoming byte)
 * The tables store negated removal terms so the per-byte delta is a pure sum
 * and the multiply K/K^2 by the previous state is the only critical-path op. */
#define GL_TABLES 3

/* Create a kernel context.
 * tables: GL_TABLES * 256 uint64 entries (canonical field elements), see above.
 * k1: the secret evaluation point K (canonical, 0 <= K < p).
 * k2: K^2 mod p.
 * aes_key: 16 bytes (AES-128).
 * kernel: one of PHTE_K_*.
 * Returns NULL on allocation/OpenSSL failure. */
GL_CTX *gl_new(const uint64_t *tables, uint64_t k1, uint64_t k2, const uint8_t aes_key[16], int kernel);

void gl_free(GL_CTX *ctx);

/* Which path this context uses: "aes-arm64", "vaes", "aes-ni" or "evp". */
const char *gl_kind(const GL_CTX *ctx);

/* Full (non-rolling) polynomial hash of the 64 bytes at q (Horner): the
 * window warm-up at the start of each chunk scan. */
uint64_t gl_digest64(const GL_CTX *ctx, const uint8_t *q);

/* Scan up to n positions. For position i (0 <= i < n), the rolling state is
 * advanced to cover the 64-byte window p[i-63..i] (reading the outgoing byte
 * at p[i-64], which the caller must guarantee to be accessible) and the cut
 * condition is evaluated on AES(state).
 * Returns the first i whose cut condition matched (state is left at position i),
 * or -1 if none matched (state is left at position n-1). */
int64_t gl_scan(GL_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask);

#endif
