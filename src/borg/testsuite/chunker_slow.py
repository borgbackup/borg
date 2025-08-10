from hashlib import sha256
from io import BytesIO

from .chunker import cf
from ..chunker import Chunker
from ..constants import *  # NOQA
from ..helpers import hex_to_bin
from . import BaseTestCase

def H(data):
    return sha256(data).digest()


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
                            chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                            runs.append(H(b''.join(chunks)))

        # The "correct" hash below matches the existing chunker behavior.
        # Future chunker optimizations must not change this, or existing repos will bloat.
        overall_hash = H(b''.join(runs))
        self.assert_equal(overall_hash, hex_to_bin("a43d0ecb3ae24f38852fcc433a83dacd28fe0748d09cc73fc11b69cf3f1a7299"))
