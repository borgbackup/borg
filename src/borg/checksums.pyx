import zlib


# Borg 2.0 repositories do not compute CRC32 over large amounts of data,
# so speed does not matter much anymore, and we can just use zlib.crc32.
crc32 = zlib.crc32
