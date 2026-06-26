from io import BytesIO
import os
import random

import pytest

from . import cf, cf_expand, make_sparsefile, make_content
from . import BS, map_sparse1, map_sparse2, map_onlysparse, map_notsparse
from ...chunkers import ChunkerFixed
from ...constants import *  # NOQA


def pretty_print(msg, items):
    """
    Pretty-print the result of get_chunks.

    For each element in the sequence:
    - If it's a bytes object consisting solely of b"H", print "header length: X" where X is its length.
    - If it's a bytes object consisting solely of b"X", print "body length: X" where X is its length.
    - If it's an int, print "sparse: length: X" where X is the integer value (interpreted as a length).
    """
    print(msg)
    print("-" * len(msg))
    for item in items:
        if isinstance(item, bytes):
            # Detect sequences of only 'H' (header) or only 'X' (body)
            if item.replace(b"H", b"") == b"":
                print(f"header({len(item)})")
            elif item.replace(b"X", b"") == b"":
                print(f"body({len(item)})")
            elif item.replace(b"\0", b"") == b"":
                print(f"zeros({len(item)})")
            else:
                # Fallback: unknown content, print as body with its length
                print(f"other({len(item)})")
        elif isinstance(item, int):
            print(f"sparse({item})")
        else:
            # Unexpected element type, just print a generic line.
            print(f"???({item})")


@pytest.mark.parametrize(
    "fname, sparse_map, header_size, sparse",
    [
        ("sparse1", map_sparse1, 0, False),
        ("sparse1", map_sparse1, 0, True),
        ("sparse1", map_sparse1, BS, False),
        ("sparse1", map_sparse1, BS, True),
        ("sparse2", map_sparse2, 0, False),
        ("sparse2", map_sparse2, 0, True),
        ("sparse2", map_sparse2, BS, False),
        ("sparse2", map_sparse2, BS, True),
        ("onlysparse", map_onlysparse, 0, False),
        ("onlysparse", map_onlysparse, 0, True),
        ("onlysparse", map_onlysparse, BS, False),
        ("onlysparse", map_onlysparse, BS, True),
        ("notsparse", map_notsparse, 0, False),
        ("notsparse", map_notsparse, 0, True),
        ("notsparse", map_notsparse, BS, False),
        ("notsparse", map_notsparse, BS, True),
    ],
)
def test_chunkify_sparse(tmpdir, fname, sparse_map, header_size, sparse):
    def get_chunks(fname, sparse, header_size):
        chunker = ChunkerFixed(BS, header_size=header_size, sparse=sparse)
        with open(fname, "rb") as fd:
            return cf(chunker.chunkify(fd))

    # this only works if sparse map blocks are same size as fixed chunker blocks
    fn = str(tmpdir / fname)
    make_sparsefile(fn, sparse_map, header_size=header_size)
    expected_content = make_content(sparse_map, header_size=header_size)
    got_chunks = get_chunks(fn, sparse=sparse, header_size=header_size)
    print(f"sparse: {sparse}")
    pretty_print("expected", expected_content)
    pretty_print("got", got_chunks)
    assert expected_content == got_chunks


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
@pytest.mark.parametrize("worker", range(os.cpu_count() or 1))
def test_fuzz_fixed(worker):
    # Fuzz fixed chunker with random and uniform data of misc. sizes.
    sizes = [random.randint(1, 4 * 1024 * 1024) for _ in range(50)]

    for block_size, header_size in [(1024, 64), (1234, 0), (4321, 123)]:
        chunker = ChunkerFixed(block_size, header_size)
        for size in sizes:
            # Random data
            data = os.urandom(size)
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            reconstructed = b"".join(parts)
            assert reconstructed == data

            # All-same data (non-zero)
            data = b"\x42" * size
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            reconstructed = b"".join(parts)
            assert reconstructed == data

            # All-zero data
            data = b"\x00" * size
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            reconstructed = b"".join(parts)
            assert reconstructed == data
