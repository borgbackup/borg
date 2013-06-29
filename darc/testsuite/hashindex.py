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
        self._generic_test(NSIndex, lambda x: (x, x), '926af057de19a82903fab517e0813e6fa16e4129df5b7062e9b1f24bbe98fb24')

    def test_chunkindex(self):
        self._generic_test(ChunkIndex, lambda x: (x, x, x), 'cc60ec9265d172b20c33b6c00160abda1a6e881d07088b9d1c5997a82e05f5a7')

