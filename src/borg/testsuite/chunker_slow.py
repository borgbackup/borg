from io import BytesIO
from binascii import unhexlify

from .chunker import cf
from ..chunker import Chunker
from ..crypto.low_level import blake2b_256
from ..constants import *  # NOQA
from . import BaseTestCase


class ChunkerRegressionTestCase(BaseTestCase):
    def test_chunkpoints_unchanged(self):
        def twist(size):
            x = 1
            a = bytearray(size)
            for i in range(size):
                x = (x * 1103515245 + 12345) & 0x7FFFFFFF
                a[i] = x & 0xFF
            return a

        data = twist(100000)

        runs = []
        for winsize in (65, 129, HASH_WINDOW_SIZE, 7351):
            for minexp in (4, 6, 7, 11, 12):
                for maxexp in (15, 17):
                    if minexp >= maxexp:
                        continue
                    for maskbits in (4, 7, 10, 12):
                        for seed in (1849058162, 1234567653):
                            fh = BytesIO(data)
                            chunker = Chunker(seed, minexp, maxexp, maskbits, winsize)
                            chunks = [blake2b_256(b"", c) for c in cf(chunker.chunkify(fh, -1))]
                            runs.append(blake2b_256(b"", b"".join(chunks)))

        # The "correct" hash below matches the existing chunker behavior.
        # Future chunker optimisations must not change this, or existing repos will bloat.
        overall_hash = blake2b_256(b"", b"".join(runs))
        self.assert_equal(overall_hash, unhexlify("b559b0ac8df8daaa221201d018815114241ea5c6609d98913cd2246a702af4e3"))
