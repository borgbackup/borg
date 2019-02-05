from .datastruct import StableDict
from ..constants import *  # NOQA

# wrapping msgpack ---------------------------------------------------------------------------------------------------
#
# due to the planned breaking api changes in upstream msgpack, we wrap it the way we need it -
# to avoid having lots of clutter in the calling code. see tickets #968 and #3632.
#
# Packing
# -------
# use_bin_type = False is needed to generate the old msgpack format (not msgpack 2.0 spec) as borg always did.
# encoding = None is needed because usage of it is deprecated
# unicode_errors = None is needed because usage of it is deprecated
#
# Unpacking
# ---------
# raw = True is needed to unpack the old msgpack format to bytes (not str, about the decoding see item.pyx).
# encoding = None is needed because usage of it is deprecated
# unicode_errors = None is needed because usage of it is deprecated

from msgpack import Packer as mp_Packer
from msgpack import packb as mp_packb
from msgpack import pack as mp_pack
from msgpack import Unpacker as mp_Unpacker
from msgpack import unpackb as mp_unpackb
from msgpack import unpack as mp_unpack

from msgpack import ExtType
from msgpack import OutOfData


class PackException(Exception):
    """Exception while msgpack packing"""


class UnpackException(Exception):
    """Exception while msgpack unpacking"""


class Packer(mp_Packer):
    def __init__(self, *, default=None, encoding=None, unicode_errors=None,
                 use_single_float=False, autoreset=True, use_bin_type=False,
                 strict_types=False):
        assert use_bin_type is False
        assert encoding is None
        assert unicode_errors is None
        super().__init__(default=default, encoding=encoding, unicode_errors=unicode_errors,
                         use_single_float=use_single_float, autoreset=autoreset, use_bin_type=use_bin_type,
                         strict_types=strict_types)

    def pack(self, obj):
        try:
            return super().pack(obj)
        except Exception as e:
            raise PackException(e)


def packb(o, *, use_bin_type=False, encoding=None, unicode_errors=None, **kwargs):
    assert use_bin_type is False
    assert encoding is None
    assert unicode_errors is None
    try:
        return mp_packb(o, use_bin_type=use_bin_type, encoding=encoding, unicode_errors=unicode_errors, **kwargs)
    except Exception as e:
        raise PackException(e)


def pack(o, stream, *, use_bin_type=False, encoding=None, unicode_errors=None, **kwargs):
    assert use_bin_type is False
    assert encoding is None
    assert unicode_errors is None
    try:
        return mp_pack(o, stream, use_bin_type=use_bin_type, encoding=encoding, unicode_errors=unicode_errors, **kwargs)
    except Exception as e:
        raise PackException(e)


# Note: after requiring msgpack >= 0.6.1 we can remove the max_*_len args and
#       rely on msgpack auto-computing DoS-safe max values from len(data) for
#       unpack(data) or from max_buffer_len for Unpacker(max_buffer_len=N).
#       maybe we can also use that to simplify get_limited_unpacker().

class Unpacker(mp_Unpacker):
    def __init__(self, file_like=None, *, read_size=0, use_list=True, raw=True,
                 object_hook=None, object_pairs_hook=None, list_hook=None,
                 encoding=None, unicode_errors=None, max_buffer_size=0,
                 ext_hook=ExtType,
                 max_str_len=2147483647,  # 2**32-1
                 max_bin_len=2147483647,
                 max_array_len=2147483647,
                 max_map_len=2147483647,
                 max_ext_len=2147483647):
        assert raw is True
        assert encoding is None
        assert unicode_errors is None
        super().__init__(file_like=file_like, read_size=read_size, use_list=use_list, raw=raw,
                         object_hook=object_hook, object_pairs_hook=object_pairs_hook, list_hook=list_hook,
                         encoding=encoding, unicode_errors=unicode_errors, max_buffer_size=max_buffer_size,
                         ext_hook=ext_hook,
                         max_str_len=max_str_len,
                         max_bin_len=max_bin_len,
                         max_array_len=max_array_len,
                         max_map_len=max_map_len,
                         max_ext_len=max_ext_len)

    def unpack(self):
        try:
            return super().unpack()
        except OutOfData:
            raise
        except Exception as e:
            raise UnpackException(e)

    def __next__(self):
        try:
            return super().__next__()
        except StopIteration:
            raise
        except Exception as e:
            raise UnpackException(e)

    next = __next__


def unpackb(packed, *, raw=True, encoding=None, unicode_errors=None,
            max_str_len=2147483647,  # 2**32-1
            max_bin_len=2147483647,
            max_array_len=2147483647,
            max_map_len=2147483647,
            max_ext_len=2147483647,
            **kwargs):
    assert raw is True
    assert encoding is None
    assert unicode_errors is None
    try:
        return mp_unpackb(packed, raw=raw, encoding=encoding, unicode_errors=unicode_errors,
                          max_str_len=max_str_len,
                          max_bin_len=max_bin_len,
                          max_array_len=max_array_len,
                          max_map_len=max_map_len,
                          max_ext_len=max_ext_len,
                          **kwargs)
    except Exception as e:
        raise UnpackException(e)


def unpack(stream, *, raw=True, encoding=None, unicode_errors=None,
           max_str_len=2147483647,  # 2**32-1
           max_bin_len=2147483647,
           max_array_len=2147483647,
           max_map_len=2147483647,
           max_ext_len=2147483647,
           **kwargs):
    assert raw is True
    assert encoding is None
    assert unicode_errors is None
    try:
        return mp_unpack(stream, raw=raw, encoding=encoding, unicode_errors=unicode_errors,
                         max_str_len=max_str_len,
                         max_bin_len=max_bin_len,
                         max_array_len=max_array_len,
                         max_map_len=max_map_len,
                         max_ext_len=max_ext_len,
                         **kwargs)
    except Exception as e:
        raise UnpackException(e)


# msgpacking related utilities -----------------------------------------------

def is_slow_msgpack():
    import msgpack
    import msgpack.fallback
    return msgpack.Packer is msgpack.fallback.Packer


def is_supported_msgpack():
    # DO NOT CHANGE OR REMOVE! See also requirements and comments in setup.py.
    import msgpack
    return (0, 5, 6) <= msgpack.version <= (0, 6, 1) and \
           msgpack.version not in []  # < blacklist bad releases here


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
                         ))
    elif kind == 'key':
        args.update(dict(use_list=True,  # default value
                         max_array_len=0,  # not used
                         max_map_len=10,  # EncryptedKey dict
                         max_str_len=4000,  # inner key data
                         object_hook=StableDict,
                         ))
    else:
        raise ValueError('kind must be "server", "client", "manifest" or "key"')
    return Unpacker(**args)


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
