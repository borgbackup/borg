/* toeplitz-aes chunker scan kernel: rolling LFSR-based Toeplitz hash with a
 * secret byte table (UHF) + AES-128 (PRF).
 *
 * See toeplitz_aes.pyx for the scheme description. This C layer only
 * implements the performance-critical inner scan: roll the tabulated
 * Toeplitz digest one byte at a time, encrypt each digest with AES-128, and
 * cut where the ciphertext's low bits (little-endian uint64 of the first 8
 * ciphertext bytes) are all zero under mask.
 *
 * Structure is identical to rabin_aes_impl.c / goldilocks_aes_impl.c (two
 * even/odd rolling lanes, groups of 8 pipelined AES blocks on the hardware
 * paths, batched OpenSSL EVP on the portable path); only the rolling
 * arithmetic differs: the digest is sum_j x^(63-j) * T[b_j] over
 * GF(2)[x] mod P, with a FIXED PUBLIC irreducible P of degree 64
 * (x^64 + x^4 + x^3 + x + 1, top bit implicit) and a secret random table T
 * of 256 uint64 values. The per-step "multiply by x" is a shift plus a
 * branchless conditional XOR of P's low bits, and both table lookups are
 * indexed by plaintext bytes, so the serial dependency chain contains no
 * loads at all. */

#ifndef BORG_TOEPLITZ_AES_IMPL_H
#define BORG_TOEPLITZ_AES_IMPL_H

#include <stdint.h>
#include <stddef.h>

typedef struct TP_CTX TP_CTX;

/* Number of 256-entry rolling tables passed to tp_new, in this order:
 * [0] in0_tbl:   T[b]              (the secret table; incoming byte, newest)
 * [1] in1_tbl:   x    * T[b] mod P (stride-2, older incoming byte)
 * [2] out64_tbl: x^64 * T[b] mod P (removal of the leaving byte)
 * [3] out65_tbl: x^65 * T[b] mod P (stride-2 removal, older leaving byte)
 * Tables 1..3 are algebraic combinations of table 0 and P; they enable the
 * two-lane (even/odd position) rolling that shortens the dependency chain. */
#define TP_TABLES 4

/* Create a kernel context.
 * tables: TP_TABLES * 256 uint64 entries, see above.
 * aes_key: 16 bytes (AES-128).
 * force_sw: nonzero forces the portable OpenSSL path (for tests/benchmarks).
 * Returns NULL on allocation/OpenSSL failure. */
TP_CTX *tp_new(const uint64_t *tables, const uint8_t aes_key[16], int force_sw);

void tp_free(TP_CTX *ctx);

/* Which path this context uses: "aes-arm64", "vaes", "aes-ni" or "evp". */
const char *tp_kind(const TP_CTX *ctx);

/* Full (non-rolling) digest of the 64 bytes at q: the window warm-up at the
 * start of each chunk scan. */
uint64_t tp_digest64(const TP_CTX *ctx, const uint8_t *q);

/* Scan up to n positions. For position i (0 <= i < n), the rolling digest is
 * advanced to cover the 64-byte window p[i-63..i] (reading the outgoing byte
 * at p[i-64], which the caller must guarantee to be accessible) and the cut
 * condition is evaluated on AES(digest).
 * Returns the first i whose cut condition matched (digest is left at position i),
 * or -1 if none matched (digest is left at position n-1). */
int64_t tp_scan(TP_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask);

#endif
