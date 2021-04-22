import stat
from collections import namedtuple

from .constants import ITEM_KEYS, ARCHIVE_KEYS
from .helpers import safe_encode, safe_decode
from .helpers import bigint_to_int, int_to_bigint
from .helpers import StableDict
from .helpers import format_file_size
from libc.string cimport memcmp
from cpython.bytes cimport PyBytes_AsStringAndSize

cdef extern from "_item.c":
    object _object_to_optr(object obj)
    object _optr_to_object(object bytes)


API_VERSION = '1.2_01'


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

    When "packing" a dict, ie. you have a dict with some data and want to convert it into an instance,
    then use eg. Item({'a': 1, ...}). This way all keys in your dictionary are validated.

    When "unpacking", that is you've read a dictionary with some data from somewhere (eg. msgpack),
    then use eg. Item(internal_dict={...}). This does not validate the keys, therefore unknown keys
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

    cdef update_internal(self, d):
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
    """return a property that deals with self._dict[key] of  PropDict"""
    cpdef readonly str key
    cpdef readonly object value_type
    cdef str value_type_name
    cpdef readonly str __doc__
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
        return value

    def __set__(self, PropDict obj, value):
        if not isinstance(value, self.value_type):
            raise TypeError(self.type_error_msg)
        if self.encode is not None:
            value = self.encode(value)
        obj._dict[self.key] = value

    def __delete__(self, PropDict instance):
        try:
            del instance._dict[self.key]
        except KeyError:
            raise AttributeError(self.attr_error_msg) from None

    cpdef __set_name__(self, name):
       self.key = name
       self.__doc__ = "%s (%s)" % (name, self.value_type_name)
       self.type_error_msg = "%s value must be %s" % (name, self.value_type_name)
       self.attr_error_msg = "attribute %s not found" % name


ChunkListEntry = namedtuple('ChunkListEntry', 'id size csize')

cdef class Item(PropDict):
    """
    Item abstraction that deals with validation and the low-level details internally:

    Items are created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to Item(internal_dict=d) and use item.key_name later.
    msgpack gives us byte-typed values for stuff that should be str, we automatically decode when getting
    such a property and encode when setting it.

    If an Item shall be serialized, give as_dict() method output to msgpack packer.

    A bug in Attic up to and including release 0.13 added a (meaningless) 'acl' key to every item.
    We must never re-use this key. See test_attic013_acl_bug for details.
    """

    VALID_KEYS = ITEM_KEYS | {'deleted', 'nlink', }

    # properties statically defined, so that IDEs can know their names:

    path = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    source = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    user = PropDictProperty((str, type(None)), 'surrogate-escaped str or None', encode=safe_encode, decode=safe_decode)
    group = PropDictProperty((str, type(None)), 'surrogate-escaped str or None', encode=safe_encode, decode=safe_decode)

    acl_access = PropDictProperty(bytes)
    acl_default = PropDictProperty(bytes)
    acl_extended = PropDictProperty(bytes)
    acl_nfs4 = PropDictProperty(bytes)

    mode = PropDictProperty(int)
    uid = PropDictProperty(int)
    gid = PropDictProperty(int)
    rdev = PropDictProperty(int)
    bsdflags = PropDictProperty(int)

    # note: we need to keep the bigint conversion for compatibility with borg 1.0 archives.
    atime = PropDictProperty(int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)
    ctime = PropDictProperty(int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)
    mtime = PropDictProperty(int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)
    birthtime = PropDictProperty(int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)

    # size is only present for items with a chunk list and then it is sum(chunk_sizes)
    # compatibility note: this is a new feature, in old archives size will be missing.
    size = PropDictProperty(int)

    hardlink_master = PropDictProperty(bool)

    chunks = PropDictProperty((list, type(None)), 'list or None')
    chunks_healthy = PropDictProperty((list, type(None)), 'list or None')

    xattrs = PropDictProperty(StableDict)

    deleted = PropDictProperty(bool)
    nlink = PropDictProperty(int)

    part = PropDictProperty(int)

    def get_size(self, hardlink_masters=None, memorize=False, compressed=False, from_chunks=False, consider_ids=None):
        """
        Determine the (uncompressed or compressed) size of this item.

        :param hardlink_masters: If given, the size of hardlink slaves is computed via the hardlink master's chunk list,
        otherwise size will be returned as 0.
        :param memorize: Whether the computed size value will be stored into the item.
        :param compressed: Whether the compressed or uncompressed size will be returned.
        :param from_chunks: If true, size is computed from chunks even if a precomputed value is available.
        :param consider_ids: Returns the size of the given ids only.
        """
        attr = 'csize' if compressed else 'size'
        assert not (compressed and memorize), 'Item does not have a csize field.'
        assert not (consider_ids is not None and memorize), "Can't store size when considering only certain ids"
        try:
            if from_chunks or consider_ids is not None:
                raise AttributeError
            size = getattr(self, attr)
        except AttributeError:
            if stat.S_ISLNK(self.mode):
                # get out of here quickly. symlinks have no own chunks, their fs size is the length of the target name.
                # also, there is the dual-use issue of .source (#2343), so don't confuse it with a hardlink slave.
                return len(self.source)
            # no precomputed (c)size value available, compute it:
            try:
                chunks = getattr(self, 'chunks')
                having_chunks = True
            except AttributeError:
                having_chunks = False
                # this item has no (own) chunks list, but if this is a hardlink slave
                # and we know the master, we can still compute the size.
                if hardlink_masters is None:
                    chunks = None
                else:
                    try:
                        master = getattr(self, 'source')
                    except AttributeError:
                        # not a hardlink slave, likely a directory or special file w/o chunks
                        chunks = None
                    else:
                        # hardlink slave, try to fetch hardlink master's chunks list
                        # todo: put precomputed size into hardlink_masters' values and use it, if present
                        chunks, _ = hardlink_masters.get(master, (None, None))
                if chunks is None:
                    return 0
            if consider_ids is not None:
                size = sum(getattr(ChunkListEntry(*chunk), attr) for chunk in chunks if chunk.id in consider_ids)
            else:
                size = sum(getattr(ChunkListEntry(*chunk), attr) for chunk in chunks)
            # if requested, memorize the precomputed (c)size for items that have an own chunks list:
            if memorize and having_chunks:
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

    def _is_type(self, typetest):
        try:
            return typetest(self.mode)
        except AttributeError:
            return False


cdef class EncryptedKey(PropDict):
    """
    EncryptedKey abstraction that deals with validation and the low-level details internally:

    A EncryptedKey is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to EncryptedKey(d) and use enc_key.xxx later.

    If a EncryptedKey shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'algorithm', 'iterations', 'salt', 'hash', 'data'}

    version = PropDictProperty(int)
    algorithm = PropDictProperty(str, encode=str.encode, decode=bytes.decode)
    iterations = PropDictProperty(int)
    salt = PropDictProperty(bytes)
    hash = PropDictProperty(bytes)
    data = PropDictProperty(bytes)


cdef class Key(PropDict):
    """
    Key abstraction that deals with validation and the low-level details internally:

    A Key is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to Key(d) and use key.xxx later.

    If a Key shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'repository_id', 'enc_key', 'enc_hmac_key', 'id_key', 'chunk_seed', 'tam_required'}

    version = PropDictProperty(int)
    repository_id = PropDictProperty(bytes)
    enc_key = PropDictProperty(bytes)
    enc_hmac_key = PropDictProperty(bytes)
    id_key = PropDictProperty(bytes)
    chunk_seed = PropDictProperty(int)
    tam_required = PropDictProperty(bool)


def tuple_encode(t):
    """encode a tuple that might contain str items"""
    # we have str, but want to give bytes to msgpack.pack
    return tuple(safe_encode(e) if isinstance(e, str) else e for e in t)


def tuple_decode(t):
    """decode a tuple that might contain bytes items"""
    # we get bytes objects from msgpack.unpack, but want str
    return tuple(safe_decode(e) if isinstance(e, bytes) else e for e in t)


cdef class ArchiveItem(PropDict):
    """
    ArchiveItem abstraction that deals with validation and the low-level details internally:

    An ArchiveItem is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to ArchiveItem(d) and use arch.xxx later.

    If a ArchiveItem shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = ARCHIVE_KEYS  # str-typed keys

    version = PropDictProperty(int)
    name = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    items = PropDictProperty(list)
    cmdline = PropDictProperty(list)  # list of s-e-str
    hostname = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    username = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    time = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    time_end = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    comment = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    chunker_params = PropDictProperty(tuple, 'chunker-params tuple', encode=tuple_encode, decode=tuple_decode)
    recreate_cmdline = PropDictProperty(list)  # list of s-e-str
    # recreate_source_id, recreate_args, recreate_partial_chunks were used in 1.1.0b1 .. b2
    recreate_source_id = PropDictProperty(bytes)
    recreate_args = PropDictProperty(list)  # list of s-e-str
    recreate_partial_chunks = PropDictProperty(list)  # list of tuples
    size = PropDictProperty(int)
    csize = PropDictProperty(int)
    nfiles = PropDictProperty(int)
    size_parts = PropDictProperty(int)
    csize_parts = PropDictProperty(int)
    nfiles_parts = PropDictProperty(int)


cdef class ManifestItem(PropDict):
    """
    ManifestItem abstraction that deals with validation and the low-level details internally:

    A ManifestItem is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to ManifestItem(d) and use manifest.xxx later.

    If a ManifestItem shall be serialized, give as_dict() method output to msgpack packer.
    """
    VALID_KEYS = {'version', 'archives', 'timestamp', 'config', 'item_keys', }

    version = PropDictProperty(int)
    archives = PropDictProperty(dict)  # name -> dict
    timestamp = PropDictProperty(str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    config = PropDictProperty(dict)
    item_keys = PropDictProperty(tuple)


cpdef _init_names():
    """
    re-implements python __set_name__
    """
    for cls in PropDict.__subclasses__():
         for name, value  in vars(cls).items():
             if isinstance(value, PropDictProperty):
                value.__set_name__(name)

_init_names()

class ItemDiff:
    """
    Comparison of two items from different archives.

    The items may have different paths and still be considered equal (e.g. for renames).
    It does not include extended or time attributes in the comparison.
    """

    def __init__(self, item1, item2, chunk_iterator1, chunk_iterator2, numeric_ids=False, can_compare_chunk_ids=False):
        self._item1 = item1
        self._item2 = item2
        self._numeric_ids = numeric_ids
        self._can_compare_chunk_ids = can_compare_chunk_ids
        self.equal = self._equal(chunk_iterator1, chunk_iterator2)
        changes = []

        if self._item1.is_link() or self._item2.is_link():
            changes.append(self._link_diff())

        if 'chunks' in self._item1 and 'chunks' in self._item2:
            changes.append(self._content_diff())

        if self._item1.is_dir() or self._item2.is_dir():
            changes.append(self._dir_diff())

        if not (self._item1.get('deleted') or self._item2.get('deleted')):
            changes.append(self._owner_diff())
            changes.append(self._mode_diff())

        # filter out empty changes
        self._changes = [ch for ch in changes if ch]

    def changes(self):
        return self._changes

    def __repr__(self):
        if self.equal:
            return 'equal'
        return ' '.join(str for d,str in self._changes)

    def _equal(self, chunk_iterator1, chunk_iterator2):
        # if both are deleted, there is nothing at path regardless of what was deleted
        if self._item1.get('deleted') and self._item2.get('deleted'):
            return True

        attr_list = ['deleted', 'mode', 'source']
        attr_list += ['uid', 'gid'] if self._numeric_ids else ['user', 'group']
        for attr in attr_list:
            if self._item1.get(attr) != self._item2.get(attr):
                return False

        if 'mode' in self._item1:     # mode of item1 and item2 is equal
            if (self._item1.is_link() and 'source' in self._item1 and 'source' in self._item2
                and self._item1.source != self._item2.source):
                return False

        if 'chunks' in self._item1 and 'chunks' in self._item2:
            return self._content_equal(chunk_iterator1, chunk_iterator2)

        return True

    def _link_diff(self):
        if self._item1.get('deleted'):
            return ({"type": 'added link'}, 'added link')
        if self._item2.get('deleted'):
            return ({"type": 'removed link'}, 'removed link')
        if 'source' in self._item1 and 'source' in self._item2 and self._item1.source != self._item2.source:
            return ({"type": 'changed link'}, 'changed link')

    def _content_diff(self):
        if self._item1.get('deleted'):
            sz = self._item2.get_size()
            return ({"type": "added", "size": sz}, 'added {:>13}'.format(format_file_size(sz)))
        if self._item2.get('deleted'):
            sz = self._item1.get_size()
            return ({"type": "removed", "size": sz}, 'removed {:>11}'.format(format_file_size(sz)))
        if not self._can_compare_chunk_ids:
            return ({"type": "modified"}, "modified")
        chunk_ids1 = {c.id for c in self._item1.chunks}
        chunk_ids2 = {c.id for c in self._item2.chunks}
        added_ids = chunk_ids2 - chunk_ids1
        removed_ids = chunk_ids1 - chunk_ids2
        added = self._item2.get_size(consider_ids=added_ids)
        removed = self._item1.get_size(consider_ids=removed_ids)
        return ({"type": "modified", "added": added, "removed": removed},
            '{:>9} {:>9}'.format(format_file_size(added, precision=1, sign=True),
            format_file_size(-removed, precision=1, sign=True)))

    def _dir_diff(self):
        if self._item2.get('deleted') and not self._item1.get('deleted'):
            return ({"type": 'removed directory'}, 'removed directory')
        if self._item1.get('deleted') and not self._item2.get('deleted'):
            return ({"type": 'added directory'}, 'added directory')

    def _owner_diff(self):
        u_attr, g_attr = ('uid', 'gid') if self._numeric_ids else ('user', 'group')
        u1, g1 = self._item1.get(u_attr), self._item1.get(g_attr)
        u2, g2 = self._item2.get(u_attr), self._item2.get(g_attr)
        if (u1, g1) != (u2, g2):
            return ({"type": "owner", "old_user": u1, "old_group": g1, "new_user": u2, "new_group": g2},
                    '[{}:{} -> {}:{}]'.format(u1, g1, u2, g2))

    def _mode_diff(self):
        if 'mode' in self._item1 and 'mode' in self._item2 and self._item1.mode != self._item2.mode:
            mode1 = stat.filemode(self._item1.mode)
            mode2 = stat.filemode(self._item2.mode)
            return ({"type": "mode", "old_mode": mode1, "new_mode": mode2}, '[{} -> {}]'.format(mode1, mode2))

    def _content_equal(self, chunk_iterator1, chunk_iterator2):
        if self._can_compare_chunk_ids:
            return self._item1.chunks == self._item2.chunks
        if self._item1.get_size() != self._item2.get_size():
            return False
        return chunks_contents_equal(chunk_iterator1, chunk_iterator2)


def chunks_contents_equal(chunks1, chunks2):
    """
    Compare chunk content and return True if they are identical.

    The chunks must be given as chunk iterators (like returned by :meth:`.DownloadPipeline.fetch_many`).
    """
    cdef:
        bytes a, b
        char * ap,
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
