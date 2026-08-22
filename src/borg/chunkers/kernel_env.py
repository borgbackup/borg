"""Shared parsing for the BORG_*_KERNEL scan-kernel selection env vars.

Unset, each chunker runs the kernel that measured fastest on this platform
(*_kernel_default() on the C side). Which one that is is not predictable from
the instruction set - an Apple M3 runs NEON 2.1x faster than the sequential
loop, while gcc on a Zen 4 runs the sequential loop 1.7x faster than AVX-512 -
so the defaults encode benchmark results, not "the widest vectors available".

A value here is a demand, not a preference: if that kernel cannot run here,
chunker creation raises ValueError rather than quietly falling back to the
default, because a silent fallback turns a benchmark or a test into a
measurement of something else.

The C side resolves names, since which names exist depends on the build and
the CPU; this module only turns its verdict into an exception.
"""

import os

# must match the FC_KSEL_* / BZ_KSEL_* / PHTE_KSEL_* codes in the C headers
KSEL_OK = 0
KSEL_UNKNOWN = 1
KSEL_NOTBUILT = 2
KSEL_NOCPU = 3


def kernel_error(envvar, want, status, valid):
    """The ValueError for a kernel request that cannot be honoured."""
    if status == KSEL_UNKNOWN:
        detail = "not a kernel of this build"
    elif status == KSEL_NOTBUILT:
        detail = "not compiled into this build (needs a newer compiler)"
    elif status == KSEL_NOCPU:
        detail = "this CPU does not support it"
    else:
        detail = "unavailable"
    return ValueError(f"{envvar}={want!r}: {detail}. Valid values: {valid}")


def requested_kernel(envvar):
    """The kernel name requested via <envvar>, or None if unset (use the default)."""
    want = os.environ.get(envvar, "").strip().lower()
    return want or None
