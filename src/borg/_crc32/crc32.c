
/* always compile slice by 8 as a runtime fallback */
#include "slice_by_8.c"

#ifdef __GNUC__
#if __x86_64__
/*
 * Because we don't want a configure script we need compiler-dependent pre-defined macros for detecting this,
 * also some compiler-dependent stuff to invoke SSE modes and align things.
 */

#define FOLDING_CRC

/*
 * SSE2 misses _mm_shuffle_epi32, and _mm_extract_epi32
 * SSSE3 added _mm_shuffle_epi32
 * SSE4.1 added _mm_extract_epi32
 * Also requires CLMUL of course (all AES-NI CPUs have it)
 * Note that there are no CPUs with AES-NI/CLMUL but without SSE4.1
 */
#define CLMUL __attribute__ ((target ("pclmul,sse4.1")))

#define ALIGNED_(n) __attribute__ ((aligned(n)))

/*
 * Work around https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56298
 * These are taken from GCC 6.x, so apparently the above bug has been resolved in that version,
 * but it still affects widely used GCC 4.x.
 * Part 2 of 2 follows below.
 */

/* clang also defines __GNUC__, but doesn't need this, it emits warnings instead */
#ifndef __clang__

#ifndef __PCLMUL__
#pragma GCC push_options
#pragma GCC target("pclmul")
#define __BORG_DISABLE_PCLMUL__
#endif

#ifndef __SSE3__
#pragma GCC push_options
#pragma GCC target("sse3")
#define __BORG_DISABLE_SSE3__
#endif

#ifndef __SSSE3__
#pragma GCC push_options
#pragma GCC target("ssse3")
#define __BORG_DISABLE_SSSE3__
#endif

#ifndef __SSE4_1__
#pragma GCC push_options
#pragma GCC target("sse4.1")
#define __BORG_DISABLE_SSE4_1__
#endif

#endif /* ifdef __clang__ */

#endif /* if __x86_64__ */
#endif /* ifdef __GNUC__ */

#ifdef FOLDING_CRC
#include "clmul.c"
#else

static uint32_t
crc32_clmul(const uint8_t *src, long len, uint32_t initial_crc)
{
    assert(0);
    return 0;
}

static int
have_clmul(void)
{
    return 0;
}
#endif

/*
 * Part 2 of 2 of the GCC workaround.
 */
#ifdef __BORG_DISABLE_PCLMUL__
#undef __BORG_DISABLE_PCLMUL__
#pragma GCC pop_options
#endif

#ifdef __BORG_DISABLE_SSE3__
#undef __BORG_DISABLE_SSE3__
#pragma GCC pop_options
#endif

#ifdef __BORG_DISABLE_SSSE3__
#undef __BORG_DISABLE_SSSE3__
#pragma GCC pop_options
#endif

#ifdef __BORG_DISABLE_SSE4_1__
#undef __BORG_DISABLE_SSE4_1__
#pragma GCC pop_options
#endif
