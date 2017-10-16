import msgpack
import msgpack.fallback

from .datastruct import StableDict
from ..constants import *  # NOQA


def is_slow_msgpack():
    return msgpack.Packer is msgpack.fallback.Packer


def get_limited_unpacker(kind):
    """return a limited Unpacker because we should not trust msgpack data received from remote"""
    args = dict(use_list=False,  # return tuples, not lists
                max_bin_len=0,  # not used
                max_ext_len=0,  # not used
                max_buffer_size=3 * max(BUFSIZE, MAX_OBJECT_SIZE),
                max_str_len=MAX_OBJECT_SIZE,  # a chunk or other repo object
                )
    if kind == 'server':
        args.update(dict(max_array_len=100,  # misc. cmd tuples
                         max_map_len=100,  # misc. cmd dicts
                         ))
    elif kind == 'client':
        args.update(dict(max_array_len=LIST_SCAN_LIMIT,  # result list from repo.list() / .scan()
                         max_map_len=100,  # misc. result dicts
                         ))
    elif kind == 'manifest':
        args.update(dict(use_list=True,  # default value
                         max_array_len=100,  # ITEM_KEYS ~= 22
                         max_map_len=MAX_ARCHIVES,  # list of archives
                         max_str_len=255,  # archive name
                         object_hook=StableDict,
                         unicode_errors='surrogateescape',
                         ))
    elif kind == 'key':
        args.update(dict(use_list=True,  # default value
                         max_array_len=0,  # not used
                         max_map_len=10,  # EncryptedKey dict
                         max_str_len=4000,  # inner key data
                         object_hook=StableDict,
                         unicode_errors='surrogateescape',
                         ))
    else:
        raise ValueError('kind must be "server", "client", "manifest" or "key"')
    return msgpack.Unpacker(**args)


def bigint_to_int(mtime):
    """Convert bytearray to int
    """
    if isinstance(mtime, bytes):
        return int.from_bytes(mtime, 'little', signed=True)
    return mtime


def int_to_bigint(value):
    """Convert integers larger than 64 bits to bytearray

    Smaller integers are left alone
    """
    if value.bit_length() > 63:
        return value.to_bytes((value.bit_length() + 9) // 8, 'little', signed=True)
    return value
