"""
Wrapping msgpack
================

We wrap ``msgpack`` here as needed to avoid clutter in the calling code.

Packing
-------
- use_bin_type = True (used by Borg since Borg 2.0)
  This is used to generate output according to new msgpack 2.0 spec.
  This cleanly keeps bytes and str types apart.

- use_bin_type = False (used by Borg < 1.3)
  This creates output according to the older msgpack spec.
  BAD: str and bytes were packed into same "raw" representation.

- unicode_errors = 'surrogateescape'
  Backup applications are one of the rare cases where this is necessary.
  It is needed because Borg also needs to deal with data that does not cleanly encode or decode using UTF-8.
  There is a lot of problematic data out there (e.g., in filenames), and as a backup tool,
  we must preserve them as faithfully as possible.

Unpacking
---------
- raw = False (used by Borg since Borg 2.0)
  We already can use this with borg 2.0 due to the type conversion to the desired type in item.py update_internal
  methods. This type conversion code can be removed in future, when we do not have to deal with data any more
  that was packed the old way.
  It will then unpack according to the msgpack 2.0 spec format and directly output bytes or str.

- raw = True (the old way, used by Borg < 1.3)

- unicode_errors = 'surrogateescape' -> see description above (will be used when raw is False).

As of Borg 2.0, we have fixed most of the `msgpack`` str/bytes issues (#968).
Borg still needs to read old repositories, archives, keys, etc., so we cannot yet fix it completely.
From now on, Borg only writes new data according to the msgpack 2.0 spec,
thus we can remove some legacy support in a later Borg release (some places are marked with "legacy").

Current behavior in msgpack terms
---------------------------------

- pack with use_bin_type=True (according to the msgpack 2.0 spec)
- packs str -> raw and bytes -> bin
- unpack with raw=False (according to the msgpack 2.0 spec, using unicode_errors='surrogateescape')
- unpacks bin to bytes and raw to str (thus we need to convert to desired type if we want bytes from "raw")
"""

from .datastruct import StableDict
from ..constants import *  # NOQA

from msgpack import Packer as mp_Packer
from msgpack import packb as mp_packb
from msgpack import pack as mp_pack
from msgpack import Unpacker as mp_Unpacker
from msgpack import unpackb as mp_unpackb
from msgpack import unpack as mp_unpack
from msgpack import version as mp_version

from msgpack import ExtType, Timestamp
from msgpack import OutOfData


version = mp_version

USE_BIN_TYPE = True
RAW = False
UNICODE_ERRORS = "surrogateescape"


class PackException(Exception):
    """Exception during msgpack packing."""


class UnpackException(Exception):
    """Exception during msgpack unpacking."""


class Packer(mp_Packer):
    def __init__(
        self,
        *,
        default=None,
        unicode_errors=UNICODE_ERRORS,
        use_single_float=False,
        autoreset=True,
        use_bin_type=USE_BIN_TYPE,
        strict_types=False,
    ):
        assert unicode_errors == UNICODE_ERRORS
        super().__init__(
            default=default,
            unicode_errors=unicode_errors,
            use_single_float=use_single_float,
            autoreset=autoreset,
            use_bin_type=use_bin_type,
            strict_types=strict_types,
        )

    def pack(self, obj):
        try:
            return super().pack(obj)
        except Exception as e:
            raise PackException(e)


def packb(o, *, use_bin_type=USE_BIN_TYPE, unicode_errors=UNICODE_ERRORS, **kwargs):
    assert unicode_errors == UNICODE_ERRORS
    try:
        return mp_packb(o, use_bin_type=use_bin_type, unicode_errors=unicode_errors, **kwargs)
    except Exception as e:
        raise PackException(e)


def pack(o, stream, *, use_bin_type=USE_BIN_TYPE, unicode_errors=UNICODE_ERRORS, **kwargs):
    assert unicode_errors == UNICODE_ERRORS
    try:
        return mp_pack(o, stream, use_bin_type=use_bin_type, unicode_errors=unicode_errors, **kwargs)
    except Exception as e:
        raise PackException(e)


class Unpacker(mp_Unpacker):
    def __init__(
        self,
        file_like=None,
        *,
        read_size=0,
        use_list=True,
        raw=RAW,
        object_hook=None,
        object_pairs_hook=None,
        list_hook=None,
        unicode_errors=UNICODE_ERRORS,
        max_buffer_size=0,
        ext_hook=ExtType,
        strict_map_key=False,
    ):
        assert raw == RAW
        assert unicode_errors == UNICODE_ERRORS
        kw = dict(
            file_like=file_like,
            read_size=read_size,
            use_list=use_list,
            raw=raw,
            object_hook=object_hook,
            object_pairs_hook=object_pairs_hook,
            list_hook=list_hook,
            unicode_errors=unicode_errors,
            max_buffer_size=max_buffer_size,
            ext_hook=ext_hook,
            strict_map_key=strict_map_key,
        )
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


def unpackb(packed, *, raw=RAW, unicode_errors=UNICODE_ERRORS, strict_map_key=False, **kwargs):
    assert raw == RAW
    assert unicode_errors == UNICODE_ERRORS
    try:
        kw = dict(raw=raw, unicode_errors=unicode_errors, strict_map_key=strict_map_key)
        kw.update(kwargs)
        return mp_unpackb(packed, **kw)
    except Exception as e:
        raise UnpackException(e)


def unpack(stream, *, raw=RAW, unicode_errors=UNICODE_ERRORS, strict_map_key=False, **kwargs):
    assert raw == RAW
    assert unicode_errors == UNICODE_ERRORS
    try:
        kw = dict(raw=raw, unicode_errors=unicode_errors, strict_map_key=strict_map_key)
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
    # DO NOT CHANGE OR REMOVE! See also requirements and comments in pyproject.toml.
    import msgpack

    if msgpack.version in []:  # < add bad releases here to deny list
        return False
    return (1, 0, 3) <= msgpack.version[:3] <= (1, 1, 1)


def get_limited_unpacker(kind):
    """return a limited Unpacker because we should not trust msgpack data received from remote"""
    # Note: msgpack >= 0.6.1 auto-computes DoS-safe max values from len(data) for
    #       unpack(data) or from max_buffer_size for Unpacker(max_buffer_size=N).
    args = dict(use_list=False, max_buffer_size=3 * max(BUFSIZE, MAX_OBJECT_SIZE))  # return tuples, not lists
    if kind in ("server", "client"):
        args.update(dict(max_buffer_size=0))  # 0 means "maximum" here, ~4GiB - needed for store_load/save
    elif kind in ("manifest", "archive", "key"):
        args.update(dict(use_list=True, object_hook=StableDict))  # default value
    else:
        raise ValueError('kind must be "server", "client", "manifest", "archive" or "key"')
    return Unpacker(**args)


def int_to_timestamp(ns):
    assert isinstance(ns, int)
    return Timestamp.from_unix_nano(ns)


def timestamp_to_int(ts):
    assert isinstance(ts, Timestamp)
    return ts.to_unix_nano()
