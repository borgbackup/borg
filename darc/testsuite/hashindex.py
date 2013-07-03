import hashlib
import tempfile
from darc.hashindex import NSIndex, ChunkIndex
from darc.testsuite import DarcTestCase


class HashIndexTestCase(DarcTestCase):

    def _generic_test(self, cls, make_value, sha):
        idx_name = tempfile.NamedTemporaryFile()
        idx = cls.create(idx_name.name)
        self.assert_equal(len(idx), 0)
        # Test set
        for x in range(100):
            idx[bytes('%-32d' % x, 'ascii')] = make_value(x)
        self.assert_equal(len(idx), 100)
        for x in range(100):
            self.assert_equal(idx[bytes('%-32d' % x, 'ascii')], make_value(x))
        # Test update
        for x in range(100):
            idx[bytes('%-32d' % x, 'ascii')] = make_value(x * 2)
        self.assert_equal(len(idx), 100)
        for x in range(100):
            self.assert_equal(idx[bytes('%-32d' % x, 'ascii')], make_value(x * 2))
        # Test delete
        for x in range(50):
            del idx[bytes('%-32d' % x, 'ascii')]
        self.assert_equal(len(idx), 50)
        del idx
        # Verify file contents
        with open(idx_name.name, 'rb') as fd:
            self.assert_equal(hashlib.sha256(fd.read()).hexdigest(), sha)
        # Make sure we can open the file
        idx = cls(idx_name.name)
        self.assert_equal(len(idx), 50)
        for x in range(50, 100):
            self.assert_equal(idx[bytes('%-32d' % x, 'ascii')], make_value(x * 2))
        idx.clear()
        self.assert_equal(len(idx), 0)
        del idx
        self.assert_equal(len(cls(idx_name.name)), 0)

    def test_nsindex(self):
        self._generic_test(NSIndex, lambda x: (x, x), '9a6f9cb3c03d83ed611265eeef1f9a9d69c2f0417a35ac14d56ce573d0c8b356')

    def test_chunkindex(self):
        self._generic_test(ChunkIndex, lambda x: (x, x, x), '9c35f237e533b6d2533d2646da127052d615ab9b66de65a795cd922b337741ca')

