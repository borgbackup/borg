def checksum(data, sum=0):
    """Simple but fast checksum that can be updated at either end.

    >>> checksum('FOOBAR')
    102367679
    >>> checksum('FOOBAR') == checksum('BAR', checksum('FOO'))
    True
    """
    s1 = sum & 0xffff
    s2 = sum >> 16
    for c in data:
        s1 += ord(c) + 1
        s2 += s1
    return ((s2 & 0xffff) << 16) + (s1 & 0xffff)


def roll_checksum(sum, remove, add, len):
    """
    >>> roll_checksum(checksum('XFOOBA'), 'X', 'R', 6) == checksum('FOOBAR')
    True
    """
    s1 = sum & 0xffff
    s2 = sum >> 16
    add = ord(add)
    remove = ord(remove)
    s1 -= remove - add
    s2 -= len * (remove + 1) - s1
    return (s1 & 0xffff) + ((s2 & 0xffff) << 16)


class ChunkifyIter(object):

    def __init__(self, fd, chunk_size, window_size):
        self.fd = fd
        self.chunk_size = chunk_size
        self.window_size = window_size
        self.buf_size = self.chunk_size * 10

    def __iter__(self):
        self.data = ''
        self.done = False
        self.i = 0
        self.sum = 0
        self.last = -1
        self.initial = self.window_size
        return self

    def next(self):
        if self.done:
            raise StopIteration
        while True:
            if self.i == self.buf_size:
                diff = self.last + 1 - self.window_size
                if diff < 0:
                    import ipdb
                    ipdb.set_trace()
                self.data = self.data[diff:]
                self.last -= diff
                self.i -= diff
            if self.i == len(self.data):
                self.data += self.fd.read(self.buf_size - len(self.data))
            if self.i == len(self.data):
                if self.last < self.i - 1:
                    self.done = True
                    return self.data[self.last + 1:]
                raise StopIteration
            if self.initial:
                self.initial -= 1
                self.sum = checksum(self.data[self.i], self.sum)
            else:
                self.sum = roll_checksum(self.sum,
                                         self.data[self.i - self.window_size],
                                         self.data[self.i],
                                         self.window_size)
            self.i += 1
            if self.i == self.buf_size and self.last == -1:
                old_last = self.last
                self.last = self.i - 1
                return self.data[old_last + 1:self.last + 1]
            elif self.sum % self.chunk_size == 0:
                old_last = self.last
                self.last = self.i - 1
                return self.data[old_last + 1:self.last + 1]


def chunkify(fd, chunk_size, chunks):
    """
    >>> list(chunkify(StringIO.StringIO(''), 5, 3))
    []
    >>> list(chunkify(StringIO.StringIO('A'), 5, 3))
    ['A']
    >>> list(chunkify(StringIO.StringIO('AB'), 5, 3))
    ['AB']
    >>> list(chunkify(StringIO.StringIO('1B'), 5, 3))
    ['1', 'B']
    >>> list(chunkify(StringIO.StringIO('ABCDEFGHIJKLMNOPQ'), 5, 3))
    ['ABCD', 'EFGHI', 'JKLMN', 'OPQ']
    >>> list(chunkify(StringIO.StringIO('1ABCDEFGHIJKLMNOPQ'), 5, 3))
    ['1', 'ABCD', 'EFGHI', 'JKLMN', 'OPQ']
    >>> list(chunkify(StringIO.StringIO('12ABCDEFGHIJKLMNOPQ'), 5, 3))
    ['1', '2A', 'BCD', 'EFGHI', 'JKLMN', 'OPQ']
    >>> list(chunkify(StringIO.StringIO('12ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 5, 3))
    ['1', '2A', 'BCD', 'EFGHI', 'JKLMN', 'OPQRS', 'TUVWX', 'YZ']
    >>> list(chunkify(StringIO.StringIO('12ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 5, 3))
    ['1', '2A', 'BCD', 'EFGHI', 'JKLMN', 'OPQRS', 'TUVWX', 'YZ']
    """
    return ChunkifyIter(fd, chunk_size, chunks)

try:
    import _speedups
    checksum = _speedups.checksum
    roll_checksum = _speedups.roll_checksum
    py_chunkify = chunkify
    chunkify = _speedups.chunkify
except ImportError:
    print 'Failed to load _speedups module, things will be slow'


if __name__ == '__main__':
    import doctest
    import StringIO
    doctest.testmod()
