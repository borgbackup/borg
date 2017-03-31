"""
borg.compress
=============

Compression is applied to chunks after ID hashing (so the ID is a direct function of the
plain chunk, compression is irrelevant to it), and of course before encryption.

Borg has a flexible scheme for deciding which compression to use for chunks.

First, there is a global default set by the --compression command line option,
which sets the .compressor attribute on the Key.

For chunks that emanate from files CompressionDecider1 may set a specific
Compressor based on patterns (this is the --compression-from option). This is stored
as a Compressor instance in the "compressor" key in the Chunk's meta dictionary.

When compressing (KeyBase.compress) either the Compressor specified in the Chunk's
meta dictionary is used, or the default Compressor of the key.

The "auto" mode (e.g. --compression auto,lzma,4) is implemented as a meta Compressor,
meaning that Auto acts like a Compressor, but defers actual work to others (namely
LZ4 as a heuristic whether compression is worth it, and the specified Compressor
for the actual compression).

Decompression is normally handled through Compressor.decompress which will detect
which compressor has been used to compress the data and dispatch to the correct
decompressor.
"""

import zlib
from collections import namedtuple

try:
    import lzma
except ImportError:
    lzma = None

from .logger import create_logger
from .helpers import Buffer, DecompressionError

API_VERSION = '1.1_02'

cdef extern from "lz4.h":
    int LZ4_compress_limitedOutput(const char* source, char* dest, int inputSize, int maxOutputSize) nogil
    int LZ4_decompress_safe(const char* source, char* dest, int inputSize, int maxOutputSize) nogil
    int LZ4_compressBound(int inputSize) nogil


buffer = Buffer(bytearray, size=0)


cdef class CompressorBase:
    """
    base class for all (de)compression classes,
    also handles compression format auto detection and
    adding/stripping the ID header (which enable auto detection).
    """
    ID = b'\xFF\xFF'  # reserved and not used
                      # overwrite with a unique 2-bytes bytestring in child classes
    name = 'baseclass'

    @classmethod
    def detect(cls, data):
        return data.startswith(cls.ID)

    def __init__(self, **kwargs):
        pass

    def compress(self, data):
        # add ID bytes
        return self.ID + data

    def decompress(self, data):
        # strip ID bytes
        return data[2:]


class CNONE(CompressorBase):
    """
    none - no compression, just pass through data
    """
    ID = b'\x00\x00'
    name = 'none'

    def compress(self, data):
        return super().compress(data)

    def decompress(self, data):
        data = super().decompress(data)
        if not isinstance(data, bytes):
            data = bytes(data)
        return data


class LZ4(CompressorBase):
    """
    raw LZ4 compression / decompression (liblz4).

    Features:
        - lz4 is super fast
        - wrapper releases CPython's GIL to support multithreaded code
        - uses safe lz4 methods that never go beyond the end of the output buffer
    """
    ID = b'\x01\x00'
    name = 'lz4'

    def __init__(self, **kwargs):
        pass

    def compress(self, idata):
        if not isinstance(idata, bytes):
            idata = bytes(idata)  # code below does not work with memoryview
        cdef int isize = len(idata)
        cdef int osize
        cdef char *source = idata
        cdef char *dest
        osize = LZ4_compressBound(isize)
        buf = buffer.get(osize)
        dest = <char *> buf
        with nogil:
            osize = LZ4_compress_limitedOutput(source, dest, isize, osize)
        if not osize:
            raise Exception('lz4 compress failed')
        return super().compress(dest[:osize])

    def decompress(self, idata):
        if not isinstance(idata, bytes):
            idata = bytes(idata)  # code below does not work with memoryview
        idata = super().decompress(idata)
        cdef int isize = len(idata)
        cdef int osize
        cdef int rsize
        cdef char *source = idata
        cdef char *dest
        # a bit more than 8MB is enough for the usual data sizes yielded by the chunker.
        # allocate more if isize * 3 is already bigger, to avoid having to resize often.
        osize = max(int(1.1 * 2**23), isize * 3)
        while True:
            try:
                buf = buffer.get(osize)
            except MemoryError:
                raise DecompressionError('MemoryError')
            dest = <char *> buf
            with nogil:
                rsize = LZ4_decompress_safe(source, dest, isize, osize)
            if rsize >= 0:
                break
            if osize > 2 ** 27:  # 128MiB (should be enough, considering max. repo obj size and very good compression)
                # this is insane, get out of here
                raise DecompressionError('lz4 decompress failed')
            # likely the buffer was too small, get a bigger one:
            osize = int(1.5 * osize)
        return dest[:rsize]


class LZMA(CompressorBase):
    """
    lzma compression / decompression
    """
    ID = b'\x02\x00'
    name = 'lzma'

    def __init__(self, level=6, **kwargs):
        super().__init__(**kwargs)
        self.level = level
        if lzma is None:
            raise ValueError('No lzma support found.')

    def compress(self, data):
        # we do not need integrity checks in lzma, we do that already
        data = lzma.compress(data, preset=self.level, check=lzma.CHECK_NONE)
        return super().compress(data)

    def decompress(self, data):
        data = super().decompress(data)
        try:
            return lzma.decompress(data)
        except lzma.LZMAError as e:
            raise DecompressionError(str(e)) from None


class ZLIB(CompressorBase):
    """
    zlib compression / decompression (python stdlib)
    """
    ID = b'\x08\x00'  # not used here, see detect()
                      # avoid all 0x.8.. IDs elsewhere!
    name = 'zlib'

    @classmethod
    def detect(cls, data):
        # matches misc. patterns 0x.8.. used by zlib
        cmf, flg = data[:2]
        is_deflate = cmf & 0x0f == 8
        check_ok = (cmf * 256 + flg) % 31 == 0
        return check_ok and is_deflate

    def __init__(self, level=6, **kwargs):
        super().__init__(**kwargs)
        self.level = level

    def compress(self, data):
        # note: for compatibility no super call, do not add ID bytes
        return zlib.compress(data, self.level)

    def decompress(self, data):
        # note: for compatibility no super call, do not strip ID bytes
        try:
            return zlib.decompress(data)
        except zlib.error as e:
            raise DecompressionError(str(e)) from None


class Auto(CompressorBase):
    """
    Meta-Compressor that decides which compression to use based on LZ4's ratio.

    As a meta-Compressor the actual compression is deferred to other Compressors,
    therefore this Compressor has no ID, no detect() and no decompress().
    """

    ID = None
    name = 'auto'

    logger = create_logger('borg.debug.file-compression')

    def __init__(self, compressor):
        super().__init__()
        self.compressor = compressor
        self.lz4 = get_compressor('lz4')
        self.none = get_compressor('none')

    def compress(self, data):
        lz4_data = self.lz4.compress(data)
        if len(lz4_data) < 0.97 * len(data):
            return self.compressor.compress(data)
        elif len(lz4_data) < len(data):
            return lz4_data
        else:
            return self.none.compress(data)

    def decompress(self, data):
        raise NotImplementedError

    def detect(cls, data):
        raise NotImplementedError


# Maps valid compressor names to their class
COMPRESSOR_TABLE = {
    CNONE.name: CNONE,
    LZ4.name: LZ4,
    ZLIB.name: ZLIB,
    LZMA.name: LZMA,
    Auto.name: Auto,
}
# List of possible compression types. Does not include Auto, since it is a meta-Compressor.
COMPRESSOR_LIST = [LZ4, CNONE, ZLIB, LZMA, ]  # check fast stuff first

def get_compressor(name, **kwargs):
    cls = COMPRESSOR_TABLE[name]
    return cls(**kwargs)


class Compressor:
    """
    compresses using a compressor with given name and parameters
    decompresses everything we can handle (autodetect)
    """
    def __init__(self, name='null', **kwargs):
        self.params = kwargs
        self.compressor = get_compressor(name, **self.params)

    def compress(self, data):
        return self.compressor.compress(data)

    def decompress(self, data):
        compressor_cls = self.detect(data)
        return compressor_cls(**self.params).decompress(data)

    @staticmethod
    def detect(data):
        hdr = bytes(data[:2])  # detect() does not work with memoryview
        for cls in COMPRESSOR_LIST:
            if cls.detect(hdr):
                return cls
        else:
            raise ValueError('No decompressor for this data found: %r.', data[:2])


ComprSpec = namedtuple('ComprSpec', ('name', 'spec', 'compressor'))


def CompressionSpec(s):
    values = s.split(',')
    count = len(values)
    if count < 1:
        raise ValueError
    # --compression algo[,level]
    name = values[0]
    if name == 'none':
        return ComprSpec(name=name, spec=None, compressor=CNONE())
    elif name == 'lz4':
        return ComprSpec(name=name, spec=None, compressor=LZ4())
    if name in ('zlib', 'lzma', ):
        if count < 2:
            level = 6  # default compression level in py stdlib
        elif count == 2:
            level = int(values[1])
            if not 0 <= level <= 9:
                raise ValueError
        else:
            raise ValueError
        return ComprSpec(name=name, spec=level, compressor=get_compressor(name, level=level))
    if name == 'auto':
        if 2 <= count <= 3:
            compression = ','.join(values[1:])
        else:
            raise ValueError
        inner = CompressionSpec(compression)
        return ComprSpec(name=name, spec=inner, compressor=Auto(inner.compressor))
    raise ValueError
