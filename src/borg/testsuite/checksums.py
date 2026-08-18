import os
import random
import subprocess
import sys
import zlib

import pytest

from ..algorithms import checksums
from ..helpers import bin_to_hex, hex_to_bin

crc32_implementations = [checksums.crc32_slice_by_8]
if checksums.have_clmul:
    crc32_implementations.append(checksums.crc32_clmul)


@pytest.mark.parametrize('implementation', crc32_implementations)
def test_crc32(implementation):
    # This includes many critical values, like misc. length and misc. aligned start addresses.
    data = os.urandom(300)
    mv = memoryview(data)
    initial_crc = 0x12345678
    # start 0..15 covers every 16B alignment the folding implementation can see.
    # Only sweeping 0..3 misses the alignments that used to truncate the initial
    # value (#10150), because CPython's bytes payloads are 16B aligned.
    for start in range(0, 16):
        for length in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                       31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                       63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
                       127, 128, 129, 130, 131, 132, 133, 134, 135,
                       255, 256, 257, ]:
            d = mv[start:start+length]
            assert zlib.crc32(d, initial_crc) == implementation(d, initial_crc)



# Big enough that random start/end offsets land on every 16B alignment and
# produce large slices, i.e. the folding path with an unaligned head.
CRC32_BUFFER_SIZE = 1024 * 1024


@pytest.mark.parametrize('implementation', crc32_implementations)
def test_crc32_random_slices(implementation):
    # Random, deliberately unaligned start *and* end offsets. Slices of a bytes
    # object would be copies at a fresh 16B aligned address, so take memoryview
    # slices - those keep the offset and therefore the alignment.
    data = os.urandom(CRC32_BUFFER_SIZE)
    mv = memoryview(data)
    for _ in range(200):
        a, b = random.randrange(CRC32_BUFFER_SIZE), random.randrange(CRC32_BUFFER_SIZE)
        start, end = min(a, b), max(a, b)
        d = mv[start:end]
        for initial_crc in (0, 0x12345678, 0xffffffff):
            assert zlib.crc32(d, initial_crc) == implementation(d, initial_crc), \
                'start=%d end=%d initial_crc=%#x' % (start, end, initial_crc)


@pytest.mark.parametrize('implementation', crc32_implementations)
def test_crc32_short_slices(implementation):
    # Random start, but every end from start to start+142: walks the empty input,
    # the too-short-to-fold inputs and the folding path through every main loop /
    # epilogue fold / partial tail combination, each at whatever alignment the
    # random start happens to have.
    data = os.urandom(CRC32_BUFFER_SIZE)
    mv = memoryview(data)
    for _ in range(10):
        start = random.randrange(CRC32_BUFFER_SIZE - 143)
        # 142 = 15 (max unaligned prefix) + 64 (one full fold_4 block)
        #     + 48 (largest epilogue fold) + 15 (max partial tail)
        for end in range(start, start + 143):
            d = mv[start:end]
            for initial_crc in (0, 0x12345678, 0xffffffff):
                assert zlib.crc32(d, initial_crc) == implementation(d, initial_crc), \
                    'start=%d end=%d initial_crc=%#x' % (start, end, initial_crc)

# Runs in a subprocess: reading past the end of the buffer is a SIGSEGV, which
# would take the whole test runner down with it.
OVERREAD_CHECK = """
import ctypes, ctypes.util, mmap, sys, zlib
from borg.algorithms.checksums import crc32_clmul

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                      ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

PAGE = mmap.PAGESIZE
PROT_NONE, PROT_READ, PROT_WRITE = 0, 1, 2
MAP_PRIVATE = 0x02
MMAP_FAILED = 2 ** (8 * ctypes.sizeof(ctypes.c_void_p)) - 1

# MAP_ANONYMOUS is 0x20 on Linux and 0x1000 on the BSDs and macOS; mmap() fails
# with the wrong one, so just try both.
for MAP_ANON in (0x20, 0x1000):
    addr = libc.mmap(None, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
    if addr not in (0, MMAP_FAILED):
        break
else:
    sys.exit(0)  # can not build the trap here, do not fail the test over it

# make the page behind our buffer unreadable, so an over-read faults
if libc.mprotect(ctypes.c_void_p(addr + PAGE), PAGE, PROT_NONE) != 0:
    sys.exit(0)

for length in range(1, 16):
    data = bytes(bytearray(range(length)))
    # place the data flush against the end of the readable page
    buf = (ctypes.c_char * length).from_address(addr + PAGE - length)
    buf[:] = data
    view = memoryview(buf)
    try:
        assert crc32_clmul(view, 0x12345678) == zlib.crc32(data, 0x12345678)
    finally:
        view.release()
"""


@pytest.mark.skipif(not checksums.have_clmul, reason='needs CLMUL support')
@pytest.mark.skipif(sys.platform == 'win32', reason='needs POSIX mmap/mprotect')
def test_crc32_clmul_no_overread():
    # crc32_clmul used to load 16 bytes unconditionally for inputs of 4..15 bytes,
    # reading up to 12 bytes past the end of the buffer. That is a SIGSEGV whenever
    # the buffer ends flush against the last mapped page, see #10149.
    rc = subprocess.call([sys.executable, '-c', OVERREAD_CHECK])
    assert rc == 0, 'crc32_clmul read past the end of the buffer (subprocess rc=%r)' % rc


def test_xxh64():
    assert bin_to_hex(checksums.xxh64(b'test', 123)) == '2b81b9401bef86cf'
    assert bin_to_hex(checksums.xxh64(b'test')) == '4fdcca5ddb678139'
    assert bin_to_hex(checksums.xxh64(hex_to_bin(
        '6f663f01c118abdea553373d5eae44e7dac3b6829b46b9bbeff202b6c592c22d724'
        'fb3d25a347cca6c5b8f20d567e4bb04b9cfa85d17f691590f9a9d32e8ccc9102e9d'
        'cf8a7e6716280cd642ce48d03fdf114c9f57c20d9472bb0f81c147645e6fa3d331'))) == '35d5d2f545d9511a'


def test_streaming_xxh64():
    hasher = checksums.StreamingXXH64(123)
    hasher.update(b'te')
    hasher.update(b'st')
    assert bin_to_hex(hasher.digest()) == hasher.hexdigest() == '2b81b9401bef86cf'
