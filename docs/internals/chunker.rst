.. include:: ../global.rst.inc
.. _chunkers:

Chunkers
========

Borg splits file contents into chunks and deduplicates them: a chunk that was
already stored (same content, same id) is not stored again. The *chunker*
decides where chunk boundaries are placed. Most chunkers are *content-defined*:
boundaries depend on the data itself, so when a file changes a little (bytes
inserted or removed somewhere), boundaries after the change re-align and most
chunks are recognized as already stored.

This document describes the available chunkers and their trade-offs, twice:
first for users who just want a good choice for their situation, then in
technical depth for readers with a cryptography background.


Choosing a chunker
------------------

What the choice affects
+++++++++++++++++++++++

* **Speed** - how fast ``borg create`` can process data that is not already
  deduplicated. All chunkers are fast (hundreds of MB/s to over 1 GB/s on one
  CPU core); for many setups, disk or network is the limit, not the chunker.
* **Deduplication** - how well changed files deduplicate against their
  previous versions. All content-defined chunkers here are equally good at
  this; only the "fixed" chunker is different (see below).
* **Privacy of chunk sizes** - what somebody who can *see* your (encrypted)
  repository can learn from the sizes of the stored chunks.

The chunk-size fingerprinting threat
++++++++++++++++++++++++++++++++++++

Borg encrypts chunk contents, but whoever stores your repository (a cloud
provider, a rented server, anyone who can read the repository files) can still
see the *sizes* of your chunks. The sequence of chunk sizes of a file works
like a fingerprint: somebody who has the same file (a leaked document, a known
public file, ...) can chunk it the same way and check whether the size pattern
occurs in your repository - "does this person have a copy of X?".

Chunkers differ in how well they resist this:

* ``buzhash`` and ``buzhash64`` / ``fastcdc`` place boundaries using a rolling
  hash. ``buzhash64`` and ``fastcdc`` mix a secret key into that hash, which
  helps, but research published in 2025 showed that observing enough chunk
  boundaries of *known* data allows recovering such keys - so against a
  capable adversary who can inject or guess file contents, these chunkers do
  not reliably hide the fingerprints.
* ``rabin-aes``, ``goldilocks-aes`` and ``toeplitz-aes`` place boundaries
  using real cryptography (AES): without the key, chunk boundaries are
  indistinguishable from random and the observed sizes yield no usable
  information about the chunking secrets. This protection has a price: they
  run at roughly half the speed of ``fastcdc`` (still >600 MB/s per core on
  modern hardware).

Note: independently of the chunker, an attacker who *already knows* an exact
file and its chunking can always check whether identical chunks exist -
deduplication requires that identical content deduplicates. Also, borg can
additionally obfuscate stored chunk sizes (see ``--compression obfuscate``),
which is complementary to a fingerprinting-resistant chunker.

The chunkers at a glance
++++++++++++++++++++++++

============== ========= ============ =========================== =====================================
name           speed     dedup        fingerprinting resistance   notes
============== ========= ============ =========================== =====================================
fixed          fastest   positional   n/a (no content dependency) fixed block size; for disk images
fastcdc        fastest   good         improved, but not sound     keyed, window-less Gear hash
buzhash64      fast      good         improved, but not sound     keyed, normalized chunking
buzhash        fast      good         weak (seed only)            borg 1.x compatible dedup
toeplitz-aes   medium    good         strong (AES-based)          best collision bound, secret table
rabin-aes      medium    good         strong (AES-based)          secret polynomial + AES
goldilocks-aes slower    good         strong (AES-based)          reference construction, comparison
============== ========= ============ =========================== =====================================

Recommendations
+++++++++++++++

* **You keep deduplicating against a repo created with borg 1.x:** use
  ``buzhash`` (only it is dedup-compatible with borg 1.x).
* **General use, maximum speed:** use ``fastcdc`` (fastest) or ``buzhash64``.
* **Your repository is stored somewhere you do not fully trust and you care
  about the fingerprinting threat above:** use ``toeplitz-aes`` (or
  ``rabin-aes``; both are strong here, ``toeplitz-aes`` has the edge in
  analysis and equal speed).
* **Raw disk / VM images, fixed-layout data:** use ``fixed`` with a block
  size matching the image's internal structure; content-defined chunking
  gains little there and ``fixed`` is the fastest option.
* ``goldilocks-aes`` exists mainly as a scientific comparison baseline; it is
  as secure as the other AES chunkers but slower - prefer ``toeplitz-aes``.

All content-defined chunkers accept min/max chunk size exponents and a mask
controlling the average chunk size, and (except ``buzhash``) a normalized
chunking level that tightens the chunk size distribution; see
:ref:`data-structures` for the exact parameter formats.


Technical background
--------------------

This section assumes familiarity with universal hashing and PRFs.

Model and the broken class
++++++++++++++++++++++++++

All content-defined chunkers here are fixed-size-window chunkers (FSWC): at
stream position ``i`` a decision function looks at (at most) the last ``w``
bytes and decides "cut here or not" (plus min/max size clamping and, for most,
FastCDC-style normalized chunking with a strict/loose mask pair). The
adversary observes cut positions - equivalently, chunk sizes - possibly for
partially known or chosen plaintext.

The classic approach cuts directly on bits of a rolling hash ``H_K(window)``:
buzhash (32-bit cyclic polynomial, borg-1.x-compatible seed twist),
``buzhash64`` (CSPRNG-keyed balanced table, 4095-byte window), ``fastcdc``
(CSPRNG-keyed Gear table, window-less: bytes age out of the 64-bit state by
left shift, so the effective window is <= 64 bytes with triangular bit
influence, which is why its cut mask uses the high bits). All these hashes
are GF(2)-linear (or affine) in their key material, so every observed
boundary is an algebraic constraint on the key; "Breaking and Fixing
Content-Defined Chunking" (Truong, Merz, Scarlata, Günther, Paterson,
CCS 2025, eprint 2025/558) and "Chunking Attacks on File Backup Services"
(eprint 2025/532) give practical key-recovery attacks against this entire
class as deployed in several backup tools. Keying the tables raises the bar
but is not sound; no amount of masking fixes the output channel.

The UHF-then-PRF construction
+++++++++++++++++++++++++++++

``rabin-aes``, ``goldilocks-aes`` and ``toeplitz-aes`` implement the
provably secure construction from eprint 2025/558 ("Chk-PHTE"): a rolling
*universal hash* compresses the 64-byte window into a 64-bit digest, then
AES-128 with an independent secret key is applied to the digest (as a
little-endian u64 in bytes 0..7 of the block, zero padding), and the cut
decision looks only at the AES output: cut iff the low ``mask_bits`` bits of
the first 8 ciphertext bytes (LE) are zero. Both secrets are derived from the
repository's id key with a per-chunker domain.

Since AES output bits are pseudorandom, the only property required of the UHF
is ε-almost-universality: for fixed ``x != y``,
``Pr_K[H_K(x) = H_K(y)] <= ε``. Colliding windows necessarily receive equal
decisions - that is the *only* residual leakage - and the security bound
degrades with (number of processed positions)² * ε, so ε directly determines
how much data one chunker key can process before the guarantee becomes
vacuous. Equal-content chunks still produce equal sizes; that is inherent to
deduplication.

The window is fixed at 64 bytes for all three (hence
``chunk_min_exp >= 6``: the roll needs 64 bytes of in-chunk history at the
first legal cut position). Digest streams do not depend on where cuts happen,
so digests can be computed ahead and encrypted in batches: each kernel has
three bit-identical code paths (batched OpenSSL EVP AES-128-ECB; arm64
crypto-extension intrinsics; x86-64 AES-NI) with two even/odd rolling lanes
and groups of 8 interleaved AES blocks on the hardware paths.

The three universal hashes
++++++++++++++++++++++++++

``toeplitz-aes``
    Tabulated LFSR-based Toeplitz hashing (Krawczyk, CRYPTO '94):
    ``digest = sum_j x^(63-j) * T[b_j]`` over GF(2)[x] mod a *fixed public*
    irreducible ``P = x^64 + x^4 + x^3 + x + 1``; the secret is the uniform
    table ``T`` of 256 u64 (2 KiB). For ``x != y`` the difference is
    ``sum_v c_v * T[v]`` where some ``c_v`` is a nonzero polynomial of
    degree < 64 - invertible mod the irreducible degree-64 ``P`` - so the
    sum is uniform: **ε = 2^-64 exactly**, optimal for a 64-bit digest and
    unconditional (nothing is sampled; the bound does not depend on choosing
    a good ``P``). The roll is a shift plus a branchless masked XOR with
    only plaintext-indexed loads.

    The fixed 64-byte window is essential: the argument needs 64 *distinct*
    powers of ``x`` of degree < 64. The tempting simplification - plain
    rotations instead of the LFSR step, i.e. keyed buzhash - fails exactly
    here: rotations satisfy ``R^64 = I`` (over GF(2),
    ``x^64 - 1 = (x+1)^64``), coefficient sums can collapse to rank 1, and
    e.g. two all-same-byte windows collide with probability 1/2. The same
    algebra is why the classic buzhash window is 4095 and not 4096: with the
    window a multiple of the word size, a uniform run hashes to a constant
    independent of its byte value.

``rabin-aes``
    Rabin fingerprint over GF(2)[x] mod a *secret, random, irreducible*
    ``P`` of degree 64 (top bit implicit; table-driven rolling). Two distinct
    64-byte windows differ by a polynomial of degree <= 511, which has at
    most 7 irreducible degree-64 factors out of ~2^58 candidates:
    ε ≈ 2^-55, probabilistic over the sampled ``P``. Key material: 8 bytes
    (the polynomial), found by rejection sampling with Rabin's irreducibility
    test. Note: the reduction table is indexed by digest bits, i.e. there is
    a secret-dependent memory access in the hot loop.

``goldilocks-aes``
    The paper's reference UHF: polynomial evaluation hash over GF(p),
    p = 2^64 - 2^32 + 1, at a secret uniform point ``K``, byte-wise Horner
    over the window. The difference of two distinct windows is a nonzero
    polynomial in ``K`` of degree <= 63: ε <= 63/p ≈ 2^-58. Key material:
    8 bytes. All table indices are plaintext bytes (no secret-dependent
    loads); the rolling multiply keeps every state canonical since the state
    feeds AES verbatim. Verified bit-equivalent (states and ciphertexts) to
    the authors' artifact implementation.

Constructions considered and rejected: Gear as the UHF (triangular aging
gives ε ≈ 1/2 via the oldest byte), hardware CRC (fixed public polynomial,
unkeyable), NH/UMAC-style multilinear hashes (position-keyed, not rollable),
carryless-multiply Rabin via PMULL (measured slower than the table kernel on
Apple Silicon, and it competes with AES for the vector pipes).

Performance and limits
++++++++++++++++++++++

Measured on an Apple M-series core (1 GiB random data, parameters 19,23,21,
best of 10 runs; "nc2" = normalized chunking level 2; EVP = portable OpenSSL
path):

============== ======== ========= ==========
chunker        hw MB/s  nc2 MB/s  EVP nc2
============== ======== ========= ==========
fastcdc        1261     1324      n/a
buzhash64      974      1036      n/a
toeplitz-aes   666      713       450
rabin-aes      661      698       434
goldilocks-aes 364      394       304
============== ======== ========= ==========

Chunk-size distributions, dedup behavior and shift resilience of all
content-defined chunkers are statistically identical (the AES output is
uniform). Notably, ``toeplitz-aes`` and ``rabin-aes`` tie on the hardware
path although the Toeplitz roll is cheaper: at ~700 MB/s the grouped-AES
hardware path is AES/transfer-bound, not roll-chain-bound (the cheaper
roller shows only on the EVP path). Future speedups must therefore come
from the AES side, not the UHF.

With a 64-bit digest, the (positions)² * ε proof bound stays meaningful up
to roughly tens of GiB per chunker key (best for ``toeplitz-aes``); beyond
that no attack is known, but the guarantee is heuristic. The upgrade path
is a wider digest (e.g. two independent tables/keys filling the full AES
block), at roughly doubled rolling cost.

References
++++++++++

* K. T. Truong, S.-P. Merz, M. Scarlata, F. Günther, K. G. Paterson:
  *Breaking and Fixing Content-Defined Chunking*, ACM CCS 2025,
  https://eprint.iacr.org/2025/558
* B. Alexeev, C. Percival, Y. X. Zhang: *Chunking Attacks on File Backup
  Services using Content-Defined Chunking*, https://eprint.iacr.org/2025/532
* H. Krawczyk: *LFSR-based Hashing and Authentication*, CRYPTO '94
* D. Lemire, O. Kaser: *Faster 64-bit universal hashing using carry-less
  multiplications* (CLHASH; source of the fixed GF(2^64) polynomial)
* M. O. Rabin: *Fingerprinting by Random Polynomials*, 1981
