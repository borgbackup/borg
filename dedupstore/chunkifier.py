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
        return self

    def next(self):
        if self.done:
            raise StopIteration
        if self.extra:
            self.done = True
            return self.extra
        while True:
            if len(self.data) - self.i < self.chunk_size:
                self.data += self.fd.read(self.chunk_size * 3)
            if not self.data:
                raise StopIteration
            if self.full_sum or len(self.data) - self.i < self.chunk_size:
                self.sum = checksum(self.data[self.i:self.i + self.chunk_size])
                self.full_sum = False
                self.remove = self.data[self.i]
            else:
                self.sum = roll_checksum(self.sum, self.remove, self.data[self.i + self.chunk_size - 1], 
                                         self.chunk_size)
                self.remove = self.data[self.i]
            if len(self.data) - self.i < self.chunk_size:  # EOF?
                if len(self.data) > self.chunk_size:
                    self.extra = self.data[-self.chunk_size:]
                    return self.data[:len(self.data) - self.chunk_size]
                else:
                    self.done = True
                    return self.data
            elif self.sum in self.chunks:
                if self.i > 0:
                    chunk = self.data[:self.i]
                    self.data = self.data[self.i:]
                else:
                    chunk = self.data[:self.chunk_size]
                    self.data = self.data[self.chunk_size:]
                self.full_sum = True
                self.i = 0
                return chunk
            elif self.i == self.chunk_size:
                chunk = self.data[:self.chunk_size]
                self.data = self.data[self.chunk_size:]
                self.i = 0
                return chunk
            else:
                self.i += 1


def chunkify(fd, chunk_size, chunks):
    """
    >>> fd = StringIO.StringIO('ABCDEFGHIJKLMN')
    >>> list(chunkify(fd, 4, {}))
    ['ABCD', 'EFGH', 'IJ', 'KLMN']

    >>> fd = StringIO.StringIO('ABCDEFGHIJKLMN')
    >>> chunks = {44564754: True} # 'BCDE'
    >>> list(chunkify(fd, 4, chunks))
    ['A', 'BCDE', 'FGHI', 'J', 'KLMN']

    >>> fd = StringIO.StringIO('ABCDEFGHIJKLMN')
    >>> chunks = {44564754: True, 48496938: True} # 'BCDE', 'HIJK'
    >>> list(chunkify(fd, 4, chunks))
    ['A', 'BCDE', 'FG', 'HIJK', 'LMN']

    >>> fd = StringIO.StringIO('ABCDEFGHIJKLMN')
    >>> chunks = {43909390: True, 50463030: True} # 'ABCD', 'KLMN'
    >>> list(chunkify(fd, 4, chunks))
    ['ABCD', 'EFGH', 'IJ', 'KLMN']
    """
    return ChunkifyIter(fd, chunk_size, chunks)


if __name__ == '__main__':
    import StringIO
    import doctest
    doctest.testmod()
