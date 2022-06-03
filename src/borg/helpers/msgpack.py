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
# unicode_errors = None is needed because usage of it is deprecated
#
# Unpacking
# ---------
# raw = True is needed to unpack the old msgpack format to bytes (not str, about the decoding see item.pyx).
# unicode_errors = None is needed because usage of it is deprecated

from msgpack import Packer as mp_Packer
from msgpack import packb as mp_packb
from msgpack import pack as mp_pack
from msgpack import Unpacker as mp_Unpacker
from msgpack import unpackb as mp_unpackb
from msgpack import unpack as mp_unpack
from msgpack import version as mp_version

from msgpack import ExtType
from msgpack import OutOfData


version = mp_version


class PackException(Exception):
    """Exception while msgpack packing"""


class UnpackException(Exception):
    """Exception while msgpack unpacking"""


class Packer(mp_Packer):
    def __init__(self, *, default=None, unicode_errors=None,
                 use_single_float=False, autoreset=True, use_bin_type=False,
                 strict_types=False):
        assert unicode_errors is None
        super().__init__(default=default, unicode_errors=unicode_errors,
                         use_single_float=use_single_float, autoreset=autoreset, use_bin_type=use_bin_type,
                         strict_types=strict_types)

    def pack(self, obj):
        try:
            return super().pack(obj)
        except Exception as e:
            raise PackException(e)


def packb(o, *, use_bin_type=False, unicode_errors=None, **kwargs):
    assert unicode_errors is None
    try:
        return mp_packb(o, use_bin_type=use_bin_type, unicode_errors=unicode_errors, **kwargs)
    except Exception as e:
        raise PackException(e)


def pack(o, stream, *, use_bin_type=False, unicode_errors=None, **kwargs):
    assert unicode_errors is None
    try:
        return mp_pack(o, stream, use_bin_type=use_bin_type, unicode_errors=unicode_errors, **kwargs)
    except Exception as e:
        raise PackException(e)


class Unpacker(mp_Unpacker):
    def __init__(self, file_like=None, *, read_size=0, use_list=True, raw=True,
                 object_hook=None, object_pairs_hook=None, list_hook=None,
                 unicode_errors=None, max_buffer_size=0,
                 ext_hook=ExtType,
                 strict_map_key=False):
        assert raw is True
        assert unicode_errors is None
        kw = dict(file_like=file_like, read_size=read_size, use_list=use_list, raw=raw,
                  object_hook=object_hook, object_pairs_hook=object_pairs_hook, list_hook=list_hook,
                  unicode_errors=unicode_errors, max_buffer_size=max_buffer_size,
                  ext_hook=ext_hook,
                  strict_map_key=strict_map_key)
        super().__init__(**kw)

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


def unpackb(packed, *, raw=True, unicode_errors=None,
            strict_map_key=False,
            **kwargs):
    assert unicode_errors is None
    try:
        kw = dict(raw=raw, unicode_errors=unicode_errors,
                  strict_map_key=strict_map_key)
        kw.update(kwargs)
        return mp_unpackb(packed, **kw)
    except Exception as e:
        raise UnpackException(e)


def unpack(stream, *, raw=True, unicode_errors=None,
           strict_map_key=False,
           **kwargs):
    assert unicode_errors is None
    try:
        kw = dict(raw=raw, unicode_errors=unicode_errors,
                  strict_map_key=strict_map_key)
        kw.update(kwargs)
        return mp_unpack(stream, **kw)
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
    return (1, 0, 3) <= msgpack.version <= (1, 0, 4) and \
           msgpack.version not in []  # < add bad releases here to deny list


def get_limited_unpacker(kind):
    """return a limited Unpacker because we should not trust msgpack data received from remote"""
    # Note: msgpack >= 0.6.1 auto-computes DoS-safe max values from len(data) for
    #       unpack(data) or from max_buffer_size for Unpacker(max_buffer_size=N).
    args = dict(use_list=False,  # return tuples, not lists
                max_buffer_size=3 * max(BUFSIZE, MAX_OBJECT_SIZE),
                )
    if kind in ('server', 'client'):
        pass  # nothing special
    elif kind in ('manifest', 'key'):
        args.update(dict(use_list=True,  # default value
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
