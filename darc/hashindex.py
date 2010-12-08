import numpy
import os
import random
import shutil
import struct
import tempfile
import unittest
from UserDict import DictMixin


class HashIndexBase(DictMixin):
    EMPTY, DELETED = -1, -2
    FREE = (EMPTY, DELETED)

    i_fmt    = struct.Struct('<i')
    assert i_fmt.size == 4

    def __init__(self, path):
        self.path = path
        self.fd = open(path, 'r+')
        assert self.fd.read(len(self.MAGIC)) == self.MAGIC
        self.num_entries = self.i_fmt.unpack(self.fd.read(4))[0]
        self.buckets = numpy.memmap(self.fd, self.idx_type, offset=len(self.MAGIC) + 4)
        self.limit = 3 * self.buckets.size / 4  # 75% fill rate

    def flush(self):
        self.fd.seek(len(self.MAGIC))
        self.fd.write(self.i_fmt.pack(self.num_entries))
        self.fd.flush()
        self.buckets.flush()

    @classmethod
    def create(cls, path, capacity=1024):
        with open(path, 'wb') as fd:
            fd.write(cls.MAGIC + '\0\0\0\0')
            a = numpy.zeros(capacity, cls.idx_type)
            for i in xrange(capacity):
                a[i][1] = cls.EMPTY
            a.tofile(fd)
        return cls(path)

    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def __delitem__(self, key):
        self.buckets[self.lookup(key)][1] = self.DELETED
        self.num_entries -= 1

    def resize(self, capacity=0):
        capacity = capacity or self.buckets.size * 2
        if capacity < self.num_entries:
            raise ValueError('Too small')
        new = self.create(self.path + '.tmp', capacity)
        for key, value in self.iteritems():
            new[key] = value
        new.flush()
        os.unlink(self.path)
        os.rename(self.path + '.tmp', self.path)
        self.fd = new.fd
        self.buckets = new.buckets
        self.limit = 3 * self.buckets.size / 4


class NSIndex(HashIndexBase):
    MAGIC = 'NSINDEX'

    idx_type = numpy.dtype('V32,<i4,<i4')
    assert idx_type.itemsize == 40

    def index(self, key):
        hash = self.i_fmt.unpack(key[:4])[0]
        return hash % self.buckets.size

    def lookup(self, key):
        didx = -1
        idx = self.index(key)
        while True:
            while self.buckets[idx][1] == self.DELETED:
                if didx == -1:
                    didx = idx
                idx = (idx + 1) % self.buckets.size
            if self.buckets[idx][1] == self.EMPTY:
                raise KeyError
            if str(self.buckets[idx][0]) == key:
                if didx != -1:
                    self.buckets[didx] = self.buckets[idx]
                    self.buckets[idx][1] = self.DELETED
                    idx = didx
                return idx
            idx = (idx + 1) % self.buckets.size

    def pop(self, key):
        idx = self.lookup(key)
        band = self.buckets[idx][1]
        self.buckets[idx][1] = self.DELETED
        self.num_entries -= 1
        return band, self.buckets[idx][2]

    def __getitem__(self, key):
        idx = self.lookup(key)
        return self.buckets[idx][1], self.buckets[idx][2]

    def __setitem__(self, key, value):
        if self.num_entries >= self.limit:
            self.resize()
        try:
            idx = self.lookup(key)
            self.buckets[idx][1], self.buckets[idx][2] = value
            return
        except KeyError:
            idx = self.index(key)
            while self.buckets[idx][1] not in self.FREE:
                idx = (idx + 1) % self.buckets.size
            self.buckets[idx][1], self.buckets[idx][2] = value
            self.buckets[idx][0] = key
            self.num_entries += 1

    def iteritems(self, limit=0, marker=None):
        n = 0
        for idx in xrange(self.buckets.size):
            if self.buckets[idx][1] in self.FREE:
                continue
            key = str(self.buckets[idx][0])
            if marker and key != marker:
                continue
            elif marker:
                marker = None
            yield key, (self.buckets[idx][1], self.buckets[idx][2])
            n += 1
            if n == limit:
                return


class BandIndex(HashIndexBase):
    MAGIC = 'BANDINDEX'
    idx_type = numpy.dtype('<i4,<i2')
    assert idx_type.itemsize == 6

    def index(self, key):
        return key % self.buckets.size

    def lookup(self, key):
        didx = -1
        idx = self.index(key)
        while True:
            while self.buckets[idx][1] == self.DELETED:
                if didx == -1:
                    didx = idx
                idx = (idx + 1) % self.buckets.size
            if self.buckets[idx][1] == self.EMPTY:
                raise KeyError
            if self.buckets[idx][0] == key:
                if didx != -1:
                    self.buckets[didx] = self.buckets[idx]
                    self.buckets[idx][1] = self.DELETED
                    idx = didx
                return idx
            idx = (idx + 1) % self.buckets.size

    def pop(self, key):
        idx = self.lookup(key)
        value = self.buckets[idx][1]
        self.buckets[idx][1] = self.DELETED
        self.num_entries -= 1
        return value

    def __getitem__(self, key):
        idx = self.lookup(key)
        return self.buckets[idx][1]

    def __setitem__(self, key, value):
        if self.num_entries >= self.limit:
            self.resize()
        try:
            idx = self.lookup(key)
            self.buckets[idx][1] = value
            return
        except KeyError:
            idx = self.index(key)
            while self.buckets[idx][1] not in self.FREE:
                idx = (idx + 1) % self.buckets.size
            self.buckets[idx][1] = value
            self.buckets[idx][0] = key
            self.num_entries += 1

    def iteritems(self, limit=0, marker=None):
        n = 0
        for idx in xrange(self.buckets.size):
            if self.buckets[idx][1] in self.FREE:
                continue
            key = self.buckets[idx][0]
            if marker and key != marker:
                continue
            elif marker:
                marker = None
            yield key, self.buckets[idx][1]
            n += 1
            if n == limit:
                return


class HashIndexTestCase(unittest.TestCase):

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmppath)

    def test_bandindex(self):
        ref = {}
        idx = BandIndex.create(os.path.join(self.tmppath, 'idx'), 16)
        for x in range(1000):
            band = random.randint(0, 100)
            ref.setdefault(band, 0)
            ref[band] += 1
            idx.setdefault(band, 0)
            idx[band] += 1
        idx.flush()
        idx2 = BandIndex(os.path.join(self.tmppath, 'idx'))
        for key, value in ref.iteritems():
            self.assertEqual(idx2[key], value)


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(HashIndexTestCase)

if __name__ == '__main__':
    unittest.main()




