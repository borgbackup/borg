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

    def __init__(self, fd, chunk_size, chunks):
        self.fd = fd
        self.chunk_size = chunk_size
        self.chunks = chunks

    def __iter__(self):
        self.data = ''
        self.i = 0
        self.full_sum = True
        self.extra = None
        self.done = False
        self.buf_size = self.chunk_size * 10
        return self

    def next(self):
        o = 0
        if self.done:
            raise StopIteration
        if self.extra:
            self.done = True
            return self.extra
        while True:
            if self.i >  self.buf_size - self.chunk_size:
                self.data = self.data[self.i - o:]
                self.i = o
            if len(self.data) - self.i < self.chunk_size:
                self.data += self.fd.read(self.buf_size - len(self.data))
            if len(self.data) == self.i:
                raise StopIteration
            if len(self.data) - self.i < self.chunk_size:  # EOF?
                if o == 1:
                    self.done = True
                    return self.data[self.i - 1:]
                elif o > 1:
                    self.extra = self.data[-self.chunk_size:]
                    return self.data[-self.chunk_size - o + 1:-self.chunk_size]
                else:
                    self.done = True
                    return self.data[self.i:]
            elif o == self.chunk_size:
                return self.data[self.i-self.chunk_size:self.i]
            if self.full_sum or len(self.data) - self.i < self.chunk_size:
                self.sum = checksum(self.data[self.i:self.i + self.chunk_size])
                self.full_sum = False
                self.remove = self.data[self.i]
            else:
                self.sum = roll_checksum(self.sum, self.remove, self.data[self.i + self.chunk_size - 1], 
                                         self.chunk_size)
                self.remove = self.data[self.i]
            if self.sum in self.chunks:
                if o > 0:
                    chunk = self.data[self.i - o:self.i]
                else:
                    chunk = self.data[self.i:self.i + self.chunk_size]
                    self.i += self.chunk_size
                self.full_sum = True
                return chunk
            else:
                self.i += 1
                o += 1


def chunkify(fd, chunk_size, chunks):
    """
    >>> list(chunkify(StringIO.StringIO('A'), 4, {}))
    ['A']
    >>> list(chunkify(StringIO.StringIO('AB'), 4, {}))
    ['AB']
    >>> list(chunkify(StringIO.StringIO('ABC'), 4, {}))
    ['ABC']
    >>> list(chunkify(StringIO.StringIO('ABCD'), 4, {}))
    ['ABCD']
    >>> list(chunkify(StringIO.StringIO('ABCDE'), 4, {}))
    ['A', 'BCDE']
    >>> list(chunkify(StringIO.StringIO('ABCDEF'), 4, {}))
    ['AB', 'CDEF']
    >>> list(chunkify(StringIO.StringIO('ABCDEFG'), 4, {}))
    ['ABC', 'DEFG']
    >>> list(chunkify(StringIO.StringIO('ABCDEFGH'), 4, {}))
    ['ABCD', 'EFGH']
    >>> list(chunkify(StringIO.StringIO('ABCDEFGHI'), 4, {}))
    ['ABCD', 'E', 'FGHI']

    >>> list(chunkify(StringIO.StringIO('ABCDEFGHIJKLMN'), 4, {}))
    ['ABCD', 'EFGH', 'IJ', 'KLMN']

    >>> chunks = {44564754: True} # 'BCDE'
    >>> list(chunkify(StringIO.StringIO('ABCDEFGHIJKLMN'), 4, chunks))
    ['A', 'BCDE', 'FGHI', 'J', 'KLMN']

    >>> chunks = {44564754: True, 48496938: True} # 'BCDE', 'HIJK'
    >>> list(chunkify(StringIO.StringIO('ABCDEFGHIJKLMN'), 4, chunks))
    ['A', 'BCDE', 'FG', 'HIJK', 'LMN']

    >>> chunks = {43909390: True, 50463030: True} # 'ABCD', 'KLMN'
    >>> list(chunkify(StringIO.StringIO('ABCDEFGHIJKLMN'), 4, chunks))
    ['ABCD', 'EFGH', 'IJ', 'KLMN']
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
    doctest.testmod()
