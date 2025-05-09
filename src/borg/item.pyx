import stat
from collections import namedtuple

from libc.string cimport memcmp
from cpython.bytes cimport PyBytes_AsStringAndSize

from .constants import ITEM_KEYS, ARCHIVE_KEYS
from .helpers import StableDict
from .helpers import format_file_size
from .helpers.fs import assert_sanitized_path, to_sanitized_path
from .helpers.msgpack import timestamp_to_int, int_to_timestamp, Timestamp
from .helpers.time import OutputTimestamp, safe_timestamp


cdef extern from "_item.c":
    object _object_to_optr(object obj)
    object _optr_to_object(object bytes)


API_VERSION = '1.2_01'


def fix_key(data, key, *, errors='strict'):
    """if k is a bytes-typed key, migrate key/value to a str-typed key in dict data"""
    if isinstance(key, bytes):
        value = data.pop(key)
        key = key.decode('utf-8', errors=errors)
        data[key] = value
    assert isinstance(key, str)
    return key


def fix_str_value(data, key, errors='surrogateescape'):
    """makes sure that data[key] is a str (decode if it is bytes)"""
    assert isinstance(key, str)  # fix_key must be called first
    value = data[key]
    value = want_str(value, errors=errors)
    data[key] = value
    return value


def fix_bytes_value(data, key):
    """makes sure that data[key] is bytes (encode if it is str)"""
    assert isinstance(key, str)  # fix_key must be called first
    value = data[key]
    value = want_bytes(value)
    data[key] = value
    return value


def fix_list_of_str(v):
    """make sure we have a list of str"""
    assert isinstance(v, (tuple, list))
    return [want_str(e) for e in v]


def fix_list_of_bytes(v):
    """make sure we have a list of bytes"""
    assert isinstance(v, (tuple, list))
    return [want_bytes(e) for e in v]


def fix_list_of_chunkentries(v):
    """make sure we have a list of correct chunkentries"""
    assert isinstance(v, (tuple, list))
    chunks = []
    for ce in v:
        assert isinstance(ce, (tuple, list))
        assert len(ce) in (2, 3)  # id, size[, csize]
        assert isinstance(ce[1], int)
        assert len(ce) == 2 or isinstance(ce[2], int)
        ce_fixed = [want_bytes(ce[0]), ce[1]]  # list! id, size only, drop csize
        chunks.append(ce_fixed)  # create a list of lists
    return chunks


def fix_tuple_of_str(v):
    """make sure we have a tuple of str"""
    assert isinstance(v, (tuple, list))
    return tuple(want_str(e) for e in v)


def fix_tuple_of_str_and_int(v):
    """make sure we have a tuple of str or int"""
    assert isinstance(v, (tuple, list))
    t = tuple(e.decode() if isinstance(e, bytes) else e for e in v)
    assert all(isinstance(e, (str, int)) for e in t), repr(t)
    return t


def fix_timestamp(v):
    """make sure v is a Timestamp"""
    if isinstance(v, Timestamp):
        return v
    # legacy support
    if isinstance(v, bytes):  # was: bigint_to_int()
        v = int.from_bytes(v, 'little', signed=True)
    assert isinstance(v, int)
    return int_to_timestamp(v)


def want_bytes(v, *, errors='surrogateescape'):
    """we know that we want bytes and the value should be bytes"""
    # legacy support: it being str can be caused by msgpack unpack decoding old data that was packed with use_bin_type=False
    if isinstance(v, str):
        v = v.encode('utf-8', errors=errors)
    assert isinstance(v, bytes), f'not a bytes object, but {v!r}'
    return v


def want_str(v, *, errors='surrogateescape'):
    """we know that we want str and the value should be str"""
    if isinstance(v, bytes):
        v = v.decode('utf-8', errors=errors)
    assert isinstance(v, str), f'not a str object, but {v!r}'
    return v


cdef class PropDict:
    """
    Manage a dictionary via properties.

    - initialization by giving a dict or kw args
    - on initialization, normalize dict keys to be str type
    - access dict via properties, like: x.key_name
    - membership check via: 'key_name' in x
    - optionally, encode when setting a value
    - optionally, decode when getting a value
    - be safe against typos in key names: check against VALID_KEYS
    - when setting a value: check type of value

    When "packing" a dict, i.e. you have a dict with some data and want to convert it into an instance,
    then use e.g. Item({'a': 1, ...}). This way all keys in your dictionary are validated.

    When "unpacking", that is you've read a dictionary with some data from somewhere (e.g. msgpack),
    then use e.g. Item(internal_dict={...}). This does not validate the keys, therefore unknown keys
    are ignored instead of causing an error.
    """
    VALID_KEYS = frozenset()  # override with <set of str> in child class

    cdef object _dict

    def __cinit__(self, data_dict=None, internal_dict=None, **kw):
        self._dict = {}
        if internal_dict is None:
            pass  # nothing to do
        elif isinstance(internal_dict, dict):
            self.update_internal(internal_dict)
        else:
            raise TypeError("internal_dict must be a dict")
        if data_dict is None:
            data = kw
        elif isinstance(data_dict, dict):
            data = data_dict
        else:
            raise TypeError("data_dict must be a dict")
        if data:
            self.update(data)

    def update(self, d):
        for k, v in d.items():
            if isinstance(k, bytes):
                k = k.decode()
            setattr(self, self._check_key(k), v)

    def update_internal(self, d):
        for k, v in d.items():
            if isinstance(k, bytes):
                k = k.decode()
            self._dict[k] = v

    def __eq__(self, other):
        return self.as_dict() == other.as_dict()

    def __repr__(self):
        return '%s(internal_dict=%r)' % (self.__class__.__name__, self._dict)

    def as_dict(self):
        """return the internal dictionary"""
        return StableDict(self._dict)

    def _check_key(self, key):
        """make sure key is of type str and known"""
        if not isinstance(key, str):
            raise TypeError("key must be str")
        if key not in self.VALID_KEYS:
            raise ValueError("key '%s' is not a valid key" % key)
        return key

    def __contains__(self, key):
        """do we have this key?"""
        return self._check_key(key) in self._dict

    def get(self, key, default=None):
        """get value for key, return default if key does not exist"""
        return getattr(self, self._check_key(key), default)


cdef class PropDictProperty:
    """return a property that deals with self._dict[key] of PropDict"""
    cdef readonly str key
    cdef readonly object value_type
    cdef str value_type_name
    cdef readonly str __doc__
    cdef object encode
    cdef object decode
    cdef str type_error_msg
    cdef str attr_error_msg

    def __cinit__(self, value_type, value_type_name=None, encode=None, decode=None):
       self.key = None
       self.value_type = value_type
       self.value_type_name = value_type_name if value_type_name is not None else value_type.__name__
       self.encode = encode
       self.decode = decode

    def __get__(self, PropDict instance, owner):
        try:
            value = instance._dict[self.key]
        except KeyError:
            raise AttributeError(self.attr_error_msg) from None
        if self.decode is not None:
            value = self.decode(value)
        if not isinstance(value, self.value_type):
            raise TypeError(self.type_error_msg)
        return value

    def __set__(self, PropDict instance, value):
        if not isinstance(value, self.value_type):
            raise TypeError(self.type_error_msg)
        if self.encode is not None:
            value = self.encode(value)
        instance._dict[self.key] = value

    def __delete__(self, PropDict instance):
        try:
            del instance._dict[self.key]
        except KeyError:
            raise AttributeError(self.attr_error_msg) from None

    cpdef __set_name__(self, owner, name):
       self.key = name
       self.__doc__ = "%s (%s)" % (name, self.value_type_name)
       self.type_error_msg = "%s value must be %s" % (name, self.value_type_name)
       self.attr_error_msg = "attribute %s not found" % name


ChunkListEntry = namedtuple('ChunkListEntry', 'id size')

cdef class Item(PropDict):
    """
    Item abstraction that deals with validation and the low-level details internally:

    Items are created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to Item(internal_dict=d) and use item.key_name later.

    If an Item shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = ITEM_KEYS | {'deleted', 'nlink', }

    # properties statically defined, so that IDEs can know their names:

    path = PropDictProperty(str, 'surrogate-escaped str', encode=assert_sanitized_path, decode=to_sanitized_path)
    source = PropDictProperty(str, 'surrogate-escaped str')  # legacy borg 1.x. borg 2: see .target
    target = PropDictProperty(str, 'surrogate-escaped str')
    user = PropDictProperty(str, 'surrogate-escaped str')
    group = PropDictProperty(str, 'surrogate-escaped str')

    acl_access = PropDictProperty(bytes)
    acl_default = PropDictProperty(bytes)
    acl_extended = PropDictProperty(bytes)
    acl_nfs4 = PropDictProperty(bytes)

    mode = PropDictProperty(int)
    uid = PropDictProperty(int)
    gid = PropDictProperty(int)
    rdev = PropDictProperty(int)
    bsdflags = PropDictProperty(int)

    atime = PropDictProperty(int, 'int (ns)', encode=int_to_timestamp, decode=timestamp_to_int)
    ctime = PropDictProperty(int, 'int (ns)', encode=int_to_timestamp, decode=timestamp_to_int)
    mtime = PropDictProperty(int, 'int (ns)', encode=int_to_timestamp, decode=timestamp_to_int)
    birthtime = PropDictProperty(int, 'int (ns)', encode=int_to_timestamp, decode=timestamp_to_int)

    # size is only present for items with a chunk list and then it is sum(chunk_sizes)
    size = PropDictProperty(int)

    inode = PropDictProperty(int)

    hlid = PropDictProperty(bytes)  # hard link id: same value means same hard link.
    hardlink_master = PropDictProperty(bool)  # legacy

    chunks = PropDictProperty(list, 'list')
    chunks_healthy = PropDictProperty(list, 'list')

    xattrs = PropDictProperty(StableDict)

    deleted = PropDictProperty(bool)
    nlink = PropDictProperty(int)

    part = PropDictProperty(int)  # legacy only

    def get_size(self, *, memorize=False, from_chunks=False, consider_ids=None):
        """
        Determine the uncompressed size of this item.

        :param memorize: Whether the computed size value will be stored into the item.
        :param from_chunks: If true, size is computed from chunks even if a precomputed value is available.
        :param consider_ids: Returns the size of the given ids only.
        """
        attr = 'size'
        assert not (consider_ids is not None and memorize), "Can't store size when considering only certain ids"
        try:
            if from_chunks or consider_ids is not None:
                raise AttributeError
            size = getattr(self, attr)
        except AttributeError:
            if stat.S_ISLNK(self.mode):
                # get out of here quickly. symlinks have no own chunks, their fs size is the length of the target name.
                if 'source' in self:  # legacy borg 1.x archives
                    return len(self.source)
                return len(self.target)
            # no precomputed (c)size value available, compute it:
            try:
                chunks = getattr(self, 'chunks')
            except AttributeError:
                return 0
            if consider_ids is not None:
                size = sum(getattr(ChunkListEntry(*chunk), attr) for chunk in chunks if chunk.id in consider_ids)
            else:
                size = sum(getattr(ChunkListEntry(*chunk), attr) for chunk in chunks)
            # if requested, memorize the precomputed (c)size for items that have an own chunks list:
            if memorize:
                setattr(self, attr, size)
        return size

    def to_optr(self):
        """
        Return an "object pointer" (optr), an opaque bag of bytes.
        The return value is effectively a reference to this object
        that can be passed exactly once to Item.from_optr to get this
        object back.

        to_optr/from_optr must be used symmetrically,
        don't call from_optr multiple times.

        This object can't be deallocated after a call to to_optr()
        until from_optr() is called.
        """
        return _object_to_optr(self)

    @classmethod
    def from_optr(self, optr):
        return _optr_to_object(optr)

    @classmethod
    def create_deleted(cls, path):
        return cls(deleted=True, chunks=[], mode=0, path=path)

    def is_link(self):
        return self._is_type(stat.S_ISLNK)

    def is_dir(self):
        return self._is_type(stat.S_ISDIR)

    def is_fifo(self):
        return self._is_type(stat.S_ISFIFO)

    def is_blk(self):
        return self._is_type(stat.S_ISBLK)

    def is_chr(self):
        return self._is_type(stat.S_ISCHR)

    def _is_type(self, typetest):
        try:
            return typetest(self.mode)
        except AttributeError:
            return False

    def update_internal(self, d):
        # legacy support for migration (data from old msgpacks comes in as bytes always, but sometimes we want str),
        # also need to fix old timestamp data types.
        for k, v in list(d.items()):
            k = fix_key(d, k)
            if k in ('user', 'group') and d[k] is None:
                # borg 1 stored some "not known" values with a None value.
                # borg 2 policy for such cases is to just not have the key/value pair.
                continue
            if k in ('path', 'source', 'target', 'user', 'group'):
                v = fix_str_value(d, k)
            if k in ('chunks', 'chunks_healthy'):
                v = fix_list_of_chunkentries(v)
            if k in ('atime', 'ctime', 'mtime', 'birthtime'):
                v = fix_timestamp(v)
            if k in ('acl_access', 'acl_default', 'acl_extended', 'acl_nfs4'):
                v = fix_bytes_value(d, k)
            if k == 'xattrs':
                if not isinstance(v, StableDict):
                    v = StableDict(v)
                v_new = StableDict()
                for xk, xv in list(v.items()):
                    xk = want_bytes(xk)
                    # old borg used to store None instead of a b'' value
                    xv = b'' if xv is None else want_bytes(xv)
                    v_new[xk] = xv
                v = v_new  # xattrs is a StableDict(bytes keys -> bytes values)
            self._dict[k] = v


cdef class EncryptedKey(PropDict):
    """
    EncryptedKey abstraction that deals with validation and the low-level details internally:

    A EncryptedKey is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to EncryptedKey(d) and use enc_key.xxx later.

    If a EncryptedKey shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'algorithm', 'iterations', 'salt', 'hash', 'data',
                  'argon2_time_cost', 'argon2_memory_cost', 'argon2_parallelism', 'argon2_type'}

    version = PropDictProperty(int)
    algorithm = PropDictProperty(str)
    iterations = PropDictProperty(int)
    salt = PropDictProperty(bytes)
    hash = PropDictProperty(bytes)
    data = PropDictProperty(bytes)
    argon2_time_cost = PropDictProperty(int)
    argon2_memory_cost = PropDictProperty(int)
    argon2_parallelism = PropDictProperty(int)
    argon2_type = PropDictProperty(str)

    def update_internal(self, d):
        # legacy support for migration (data from old msgpacks comes in as bytes always, but sometimes we want str)
        for k, v in list(d.items()):
            k = fix_key(d, k)
            if k == 'version':
                assert isinstance(v, int)
            if k in ('algorithm', 'argon2_type'):
                v = fix_str_value(d, k)
            if k in ('salt', 'hash', 'data'):
                v = fix_bytes_value(d, k)
            self._dict[k] = v


cdef class Key(PropDict):
    """
    Key abstraction that deals with validation and the low-level details internally:

    A Key is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to Key(d) and use key.xxx later.

    If a Key shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'repository_id', 'crypt_key', 'id_key', 'chunk_seed', 'tam_required'}

    version = PropDictProperty(int)
    repository_id = PropDictProperty(bytes)
    crypt_key = PropDictProperty(bytes)
    id_key = PropDictProperty(bytes)
    chunk_seed = PropDictProperty(int)
    tam_required = PropDictProperty(bool)  # legacy. borg now implicitly always requires TAM.

    def update_internal(self, d):
        # legacy support for migration (data from old msgpacks comes in as bytes always, but sometimes we want str)
        for k, v in list(d.items()):
            k = fix_key(d, k)
            if k == 'version':
                assert isinstance(v, int)
            if k in ('repository_id', 'crypt_key', 'id_key'):
                v = fix_bytes_value(d, k)
            self._dict[k] = v
        if 'crypt_key' not in self._dict:  # legacy, we're loading an old v1 key
            k = fix_bytes_value(d, 'enc_key') + fix_bytes_value(d, 'enc_hmac_key')
            assert isinstance(k, bytes), "k == %r" % k
            assert len(k) in (32 + 32, 32 + 128)  # 256+256 or 256+1024 bits
            self._dict['crypt_key'] = k

cdef class ArchiveItem(PropDict):
    """
    ArchiveItem abstraction that deals with validation and the low-level details internally:

    An ArchiveItem is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to ArchiveItem(d) and use arch.xxx later.

    If a ArchiveItem shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = ARCHIVE_KEYS

    version = PropDictProperty(int)
    name = PropDictProperty(str, 'surrogate-escaped str')
    items = PropDictProperty(list)  # list of chunk ids of item metadata stream (only in memory)
    item_ptrs = PropDictProperty(list)  # list of blocks with list of chunk ids of ims, arch v2
    cmdline = PropDictProperty(list)  # legacy, list of s-e-str
    command_line = PropDictProperty(str, 'surrogate-escaped str')
    hostname = PropDictProperty(str, 'surrogate-escaped str')
    username = PropDictProperty(str, 'surrogate-escaped str')
    time = PropDictProperty(str)
    time_end = PropDictProperty(str)
    comment = PropDictProperty(str, 'surrogate-escaped str')
    tags = PropDictProperty(list)  # list of s-e-str
    chunker_params = PropDictProperty(tuple)
    recreate_cmdline = PropDictProperty(list)  # legacy, list of s-e-str
    recreate_command_line = PropDictProperty(str, 'surrogate-escaped str')
    # recreate_source_id, recreate_args, recreate_partial_chunks were used in 1.1.0b1 .. b2
    recreate_source_id = PropDictProperty(bytes)
    recreate_args = PropDictProperty(list)  # list of s-e-str
    recreate_partial_chunks = PropDictProperty(list)  # list of tuples
    size = PropDictProperty(int)
    nfiles = PropDictProperty(int)
    size_parts = PropDictProperty(int)  # legacy only
    nfiles_parts = PropDictProperty(int)  # legacy only

    def update_internal(self, d):
        # legacy support for migration (data from old msgpacks comes in as bytes always, but sometimes we want str)
        for k, v in list(d.items()):
            k = fix_key(d, k)
            if k == 'version':
                assert isinstance(v, int)
            if k in ('name', 'hostname', 'username', 'comment'):
                v = fix_str_value(d, k)
            if k in ('time', 'time_end'):
                v = fix_str_value(d, k, 'replace')
            if k == 'chunker_params':
                v = fix_tuple_of_str_and_int(v)
            if k in ('command_line', 'recreate_command_line'):
                v = fix_str_value(d, k)
            if k in ('cmdline', 'recreate_cmdline'):  # legacy
                v = fix_list_of_str(v)
            if k == 'items':  # legacy
                v = fix_list_of_bytes(v)
            if k == 'item_ptrs':
                v = fix_list_of_bytes(v)
            self._dict[k] = v


cdef class ManifestItem(PropDict):
    """
    ManifestItem abstraction that deals with validation and the low-level details internally:

    A ManifestItem is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to ManifestItem(d) and use manifest.xxx later.

    If a ManifestItem shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'archives', 'timestamp', 'config', 'item_keys', }

    version = PropDictProperty(int)
    archives = PropDictProperty(dict, 'dict of str -> dict')  # name -> dict
    timestamp = PropDictProperty(str)
    config = PropDictProperty(dict)
    item_keys = PropDictProperty(tuple, 'tuple of str')  # legacy. new location is inside config.

    def update_internal(self, d):
        # legacy support for migration (data from old msgpacks comes in as bytes always, but sometimes we want str)
        for k, v in list(d.items()):
            k = fix_key(d, k)
            if k == 'version':
                assert isinstance(v, int)
            if k == 'archives':
                ad = v
                assert isinstance(ad, dict)
                for ak, av in list(ad.items()):
                    ak = fix_key(ad, ak, errors='surrogateescape')
                    assert isinstance(av, dict)
                    for ik, iv in list(av.items()):
                        ik = fix_key(av, ik)
                        if ik == 'id':
                            fix_bytes_value(av, 'id')
                        if ik == 'time':
                            fix_str_value(av, 'time')
                    assert set(av) == {'id', 'time'}
            if k == 'timestamp':
                v = fix_str_value(d, k, 'replace')
            if k == 'config':
                cd = v
                assert isinstance(cd, dict)
                for ck, cv in list(cd.items()):
                    ck = fix_key(cd, ck)
                    if ck == 'tam_required':
                        assert isinstance(cv, bool)
                    if ck == 'feature_flags':
                        assert isinstance(cv, dict)
                        ops = {'read', 'check', 'write', 'delete'}
                        for op, specs in list(cv.items()):
                            op = fix_key(cv, op)
                            assert op in ops
                            for speck, specv in list(specs.items()):
                                speck = fix_key(specs, speck)
                                if speck == 'mandatory':
                                    specs[speck] = fix_tuple_of_str(specv)
                        assert set(cv).issubset(ops)
            if k == 'item_keys':
                v = fix_tuple_of_str(v)
            self._dict[k] = v


cpdef _init_names():
    """
    re-implements python __set_name__ for Cython<3.1
    """
    for cls in PropDict.__subclasses__():
        for name, value in vars(cls).items():
            if isinstance(value, PropDictProperty):
                value.__set_name__(cls, name)

_init_names()


class DiffChange:
    """
    Stores a change in a diff.

    The diff_type denotes the type of change, e.g. "added", "removed", "modified".
    The diff_data contains additional information about the change, e.g. the old and new mode.
    """
    def __init__(self, diff_type, diff_data=None):
        self.diff_type = diff_type
        self.diff_data = diff_data or {}

    def to_dict(self):
        return {"type": self.diff_type, **self.diff_data}


class ItemDiff:
    """
    Comparison of two items from different archives.

    The items may have different paths and still be considered equal (e.g. for renames).
    """

    def __init__(self, path, item1, item2, chunk_1, chunk_2, numeric_ids=False, can_compare_chunk_ids=False):
        self.path = path
        self._item1 = item1
        self._item2 = item2
        self._numeric_ids = numeric_ids
        self._can_compare_chunk_ids = can_compare_chunk_ids
        self._chunk_1 = chunk_1
        self._chunk_2 = chunk_2
        self._changes = {}

        if self._item1.is_link() or self._item2.is_link():
            self._link_diff()

        if 'chunks' in self._item1 and 'chunks' in self._item2:
            self._content_diff()

        if self._item1.is_dir() or self._item2.is_dir():
            self._presence_diff('directory')

        if self._item1.is_blk() or self._item2.is_blk():
            self._presence_diff('blkdev')

        if self._item1.is_chr() or self._item2.is_chr():
            self._presence_diff('chrdev')

        if self._item1.is_fifo() or self._item2.is_fifo():
            self._presence_diff('fifo')

        if not (self._item1.get('deleted') or self._item2.get('deleted')):
            self._owner_diff()
            self._mode_diff()
            self._time_diffs()


    def changes(self):
        return self._changes

    def __repr__(self):
        return (' '.join(self._changes.keys())) or 'equal'

    def equal(self, content_only=False):
        # if both are deleted, there is nothing at path regardless of what was deleted
        if self._item1.get('deleted') and self._item2.get('deleted'):
            return True

        attr_list = ['deleted', 'target']
        if not content_only:
            attr_list += ['mode', 'ctime', 'mtime']
            attr_list += ['uid', 'gid'] if self._numeric_ids else ['user', 'group']

        for attr in attr_list:
            if self._item1.get(attr) != self._item2.get(attr):
                return False

        if 'mode' in self._item1:     # mode of item1 and item2 is equal
            if (self._item1.is_link() and 'target' in self._item1 and 'target' in self._item2
                and self._item1.target != self._item2.target):
                return False

        if 'chunks' in self._item1 and 'chunks' in self._item2:
            return self._content_equal()

        return True

    def _presence_diff(self, item_type):
        if not self._item1.get('deleted') and self._item2.get('deleted'):
            self._changes[item_type] = DiffChange(f"removed {item_type}")
            return True
        if self._item1.get('deleted') and not self._item2.get('deleted'):
            self._changes[item_type] = DiffChange(f"added {item_type}")
            return True

    def _link_diff(self):
        if self._presence_diff('link'):
            return True
        if 'target' in self._item1 and 'target' in self._item2 and self._item1.target != self._item2.target:
            self._changes['link'] = DiffChange('changed link')
            return True

    def _content_diff(self):
        if self._item1.get('deleted'):
            sz = self._item2.get_size()
            self._changes['content'] = DiffChange("added", {"added": sz, "removed": 0})
            return True
        if self._item2.get('deleted'):
            sz = self._item1.get_size()
            self._changes['content'] = DiffChange("removed", {"added": 0, "removed": sz})
            return True
        if not self._can_compare_chunk_ids:
            self._changes['content'] = DiffChange("modified")
            return True
        chunk_ids1 = {c.id for c in self._item1.chunks}
        chunk_ids2 = {c.id for c in self._item2.chunks}
        added_ids = chunk_ids2 - chunk_ids1
        removed_ids = chunk_ids1 - chunk_ids2
        added = self._item2.get_size(consider_ids=added_ids)
        removed = self._item1.get_size(consider_ids=removed_ids)
        self._changes['content'] = DiffChange("modified", {"added": added, "removed": removed})
        return True


    def _owner_diff(self):
        u_attr, g_attr = ('uid', 'gid') if self._numeric_ids else ('user', 'group')
        u1, g1 = self._item1.get(u_attr), self._item1.get(g_attr)
        u2, g2 = self._item2.get(u_attr), self._item2.get(g_attr)
        if (u1, g1) == (u2, g2):
            return False
        self._changes['owner'] = DiffChange("changed owner", {"item1": (u1, g1), "item2": (u2, g2)})
        if u1 != u2:
            self._changes['user'] = DiffChange("changed user", {"item1": u1, "item2": u2})
        if g1 != g2:
            self._changes['group'] = DiffChange("changed group", {"item1": g1, "item2": g2})
        return True

    def _mode_diff(self):
        if 'mode' in self._item1 and 'mode' in self._item2 and self._item1.mode != self._item2.mode:
            mode1 = stat.filemode(self._item1.mode)
            mode2 = stat.filemode(self._item2.mode)
            self._changes['mode'] = DiffChange("changed mode", {"item1": mode1, "item2": mode2})
            if mode1[0] != mode2[0]:
                self._changes['type'] = DiffChange("changed type", {"item1": mode1[0], "item2": mode2[0]})

    def _time_diffs(self):
        attrs = ["ctime", "mtime"]
        for attr in attrs:
            if attr in self._item1 and attr in self._item2 and self._item1.get(attr) != self._item2.get(attr):
                ts1 = OutputTimestamp(safe_timestamp(self._item1.get(attr)))
                ts2 = OutputTimestamp(safe_timestamp(self._item2.get(attr)))
                self._changes[attr] = DiffChange(attr, {"item1": ts1, "item2": ts2},)
        return True

    def content(self):
        return self._changes.get('content')

    def ctime(self):
        return self._changes.get('ctime')

    def mtime(self):
        return self._changes.get('mtime')

    def mode(self):
        return self._changes.get('mode')

    def type(self):
        return self._changes.get('type')

    def owner(self):
        return self._changes.get('owner')

    def user(self):
        return self._changes.get('user')

    def group(self):
        return self._changes.get('group')

    def _content_equal(self):
        if self._can_compare_chunk_ids:
            return self._item1.chunks == self._item2.chunks
        if self._item1.get_size() != self._item2.get_size():
            return False
        return chunks_contents_equal(self._chunk_1, self._chunk_2)


def chunks_contents_equal(chunks_a, chunks_b):
    """
    Compare chunk content and return True if they are identical.

    The chunks must be given as chunk iterators (like returned by :meth:`.DownloadPipeline.fetch_many`).
    """
    cdef:
        bytes a, b
        char * ap
        char * bp
        Py_ssize_t slicelen = 0
        Py_ssize_t alen = 0
        Py_ssize_t blen = 0

    while True:
        if not alen:
            a = next(chunks_a, None)
            if a is None:
                return not blen and next(chunks_b, None) is None
            PyBytes_AsStringAndSize(a, &ap, &alen)
        if not blen:
            b = next(chunks_b, None)
            if b is None:
                return not alen and next(chunks_a, None) is None
            PyBytes_AsStringAndSize(b, &bp, &blen)
        slicelen = min(alen, blen)
        if memcmp(ap, bp, slicelen) != 0:
            return False
        ap += slicelen
        bp += slicelen
        alen -= slicelen
        blen -= slicelen
