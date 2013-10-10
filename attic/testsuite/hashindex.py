import hashlib
import os
import tempfile
from attic.hashindex import NSIndex, ChunkIndex
from attic.testsuite import AtticTestCase


class HashIndexTestCase(AtticTestCase):

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
        self._generic_test(NSIndex, lambda x: (x, x), '369a18ae6a52524eb2884a3c0fdc2824947edd017a2688c5d4d7b3510c245ab9')

    def test_chunkindex(self):
        self._generic_test(ChunkIndex, lambda x: (x, x, x), 'ed22e8a883400453c0ee79a06c54df72c994a54eeefdc6c0989efdc5ee6d07b7')

    def test_resize(self):
        n = 2000  # Must be >= MIN_BUCKETS
        idx_name = tempfile.NamedTemporaryFile()
        idx = NSIndex.create(idx_name.name)
        initial_size = os.path.getsize(idx_name.name)
        self.assert_equal(len(idx), 0)
        for x in range(n):
            idx[bytes('%-32d' % x, 'ascii')] = x, x
        idx.flush()
        self.assert_true(initial_size < os.path.getsize(idx_name.name))
        for x in range(n):
            del idx[bytes('%-32d' % x, 'ascii')]
        self.assert_equal(len(idx), 0)
        idx.flush()
        self.assert_equal(initial_size, os.path.getsize(idx_name.name))

    def test_read_only(self):
        """Make sure read_only indices work even they contain a lot of tombstones
        """
        idx_name = tempfile.NamedTemporaryFile()
        idx = NSIndex.create(idx_name.name)
        for x in range(100):
            idx[bytes('%-0.32d' % x, 'ascii')] = x, x
        for x in range(99):
            del idx[bytes('%-0.32d' % x, 'ascii')]
        idx.flush()
        idx2 = NSIndex(idx_name.name, readonly=True)
        self.assert_equal(idx2[bytes('%-0.32d' % 99, 'ascii')], (99, 99))

