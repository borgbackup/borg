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


def chunker(fd, chunk_size, chunks):
    """
    >>> fd = StringIO.StringIO('ABCDEFGHIJKLMN')
    >>> list(chunker(fd, 4, {}))
    ['ABCD', 'EFGH', 'IJ', 'KLMN']
    
    >>> fd = StringIO.StringIO('ABCDEFGHIJKLMN')
    >>> chunks = {44564754: True} # 'BCDE'
    >>> list(chunker(fd, 4, chunks))
    ['A', 'BCDE', 'FGHI', 'J', 'KLMN']

    >>> fd = StringIO.StringIO('ABCDEFGHIJKLMN')
    >>> chunks = {44564754: True, 48496938: True} # 'BCDE', 'HIJK'
    >>> list(chunker(fd, 4, chunks))
    ['A', 'BCDE', 'FG', 'HIJK', 'LMN']

    >>> fd = StringIO.StringIO('ABCDEFGHIJKLMN')
    >>> chunks = {43909390: True, 50463030: True} # 'ABCD', 'KLMN'
    >>> list(chunker(fd, 4, chunks))
    ['ABCD', 'EFGH', 'IJ', 'KLMN']
    """
    data = 'X' + fd.read(chunk_size * 3)
    i = 1
    sum = checksum(data[:chunk_size])
    while True:
        if len(data) - i <= chunk_size * 2:
            data += fd.read(chunk_size * 2)
        if i == chunk_size + 1:
            yield data[1:chunk_size + 1]
            i = 1
            data = data[chunk_size:]
        if len(data) - i <= chunk_size:  # EOF?
            if len(data) > chunk_size + 1:
                yield data[1:len(data) - chunk_size]
                yield data[:chunk_size]
            else:
                yield data[1:]
            return
        sum = roll_checksum(sum, data[i - 1], data[i - 1 + chunk_size], chunk_size)
        #print data[i:i + chunk_size], sum
        if chunks.get(sum):
            if i > 1:
                yield data[1:i]
            yield data[i:i + chunk_size]
            data = data[i + chunk_size - 1:]
            i = 0
            sum = checksum(data[:chunk_size])
        i += 1

if __name__ == '__main__':
    import StringIO
    import doctest
    doctest.testmod()
