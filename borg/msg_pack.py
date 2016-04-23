# this is a wrapper around msgpack that fixes some bad defaults.
# - we want bytes -> pack -> unpack -> bytes
# - we want str -> pack -> unpack -> str (and use utf-8 encoding)

import msgpack
import msgpack.fallback

msgpack_packb = msgpack.packb
msgpack_unpackb = msgpack.unpackb


def is_slow():
    return msgpack.Packer is msgpack.fallback.Packer


def packb(data, **kw):
    return msgpack_packb(data, encoding='utf-8', use_bin_type=True, **kw)


def unpackb(data, **kw):
    return msgpack_unpackb(data, encoding='utf-8', **kw)


class Packer(msgpack.Packer):
    def __init__(self,
                 default=None,
                 encoding='utf-8',
                 unicode_errors='strict',
                 use_single_float=False,
                 autoreset=1,
                 use_bin_type=1,  # different from base class
                 ):
        super().__init__(
            default=default,
            encoding=encoding,
            unicode_errors=unicode_errors,
            use_single_float=use_single_float,
            autoreset=autoreset,
            use_bin_type=use_bin_type,
        )


class Unpacker(msgpack.Unpacker):
    def __init__(self,
                 file_like=None,
                 read_size=0,
                 use_list=1,
                 object_hook=None,
                 object_pairs_hook=None,
                 list_hook=None,
                 encoding='utf-8',  # different from base class
                 unicode_errors='strict',
                 max_buffer_size=0,
                 ext_hook=None,
                 max_str_len=2147483647,
                 max_bin_len=2147483647,
                 max_array_len=2147483647,
                 max_map_len=2147483647,
                 max_ext_len=2147483647,
                 ):
        super().__init__(
            file_like=file_like,
            read_size=read_size,
            use_list=use_list,
            object_hook=object_hook,
            object_pairs_hook=object_pairs_hook,
            list_hook=list_hook,
            encoding=encoding,
            unicode_errors=unicode_errors,
            max_buffer_size=max_buffer_size,
            ext_hook=ext_hook,
            max_str_len=max_str_len,
            max_bin_len=max_bin_len,
            max_array_len=max_array_len,
            max_map_len=max_map_len,
            max_ext_len=max_ext_len,
        )
