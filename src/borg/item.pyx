import stat
from collections import namedtuple

from .constants import ITEM_KEYS, ARCHIVE_KEYS
from .helpers import safe_encode, safe_decode
from .helpers import bigint_to_int, int_to_bigint
from .helpers import StableDict
from .helpers import format_file_size

cdef extern from "_item.c":
    object _object_to_optr(object obj)
    object _optr_to_object(object bytes)


API_VERSION = '1.2_01'


class PropDict:
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
    VALID_KEYS = None  # override with <set of str> in child class

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    def __init__(self, data_dict=None, internal_dict=None, **kw):
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

    @staticmethod
    def _make_property(key, value_type, value_type_name=None, encode=None, decode=None):
        """return a property that deals with self._dict[key]"""
        assert isinstance(key, str)
        if value_type_name is None:
            value_type_name = value_type.__name__
        doc = "%s (%s)" % (key, value_type_name)
        type_error_msg = "%s value must be %s" % (key, value_type_name)
        attr_error_msg = "attribute %s not found" % key

        def _get(self):
            try:
                value = self._dict[key]
            except KeyError:
                raise AttributeError(attr_error_msg) from None
            if decode is not None:
                value = decode(value)
            return value

        def _set(self, value):
            if not isinstance(value, value_type):
                raise TypeError(type_error_msg)
            if encode is not None:
                value = encode(value)
            self._dict[key] = value

        def _del(self):
            try:
                del self._dict[key]
            except KeyError:
                raise AttributeError(attr_error_msg) from None

        return property(_get, _set, _del, doc=doc)


ChunkListEntry = namedtuple('ChunkListEntry', 'id size csize')

class Item(PropDict):
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

    VALID_KEYS = ITEM_KEYS | {'deleted', 'nlink', }  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    # properties statically defined, so that IDEs can know their names:

    path = PropDict._make_property('path', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    source = PropDict._make_property('source', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    user = PropDict._make_property('user', (str, type(None)), 'surrogate-escaped str or None', encode=safe_encode, decode=safe_decode)
    group = PropDict._make_property('group', (str, type(None)), 'surrogate-escaped str or None', encode=safe_encode, decode=safe_decode)

    acl_access = PropDict._make_property('acl_access', bytes)
    acl_default = PropDict._make_property('acl_default', bytes)
    acl_extended = PropDict._make_property('acl_extended', bytes)
    acl_nfs4 = PropDict._make_property('acl_nfs4', bytes)

    mode = PropDict._make_property('mode', int)
    uid = PropDict._make_property('uid', int)
    gid = PropDict._make_property('gid', int)
    rdev = PropDict._make_property('rdev', int)
    bsdflags = PropDict._make_property('bsdflags', int)

    # note: we need to keep the bigint conversion for compatibility with borg 1.0 archives.
    atime = PropDict._make_property('atime', int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)
    ctime = PropDict._make_property('ctime', int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)
    mtime = PropDict._make_property('mtime', int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)
    birthtime = PropDict._make_property('birthtime', int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)

    # size is only present for items with a chunk list and then it is sum(chunk_sizes)
    # compatibility note: this is a new feature, in old archives size will be missing.
    size = PropDict._make_property('size', int)

    hardlink_master = PropDict._make_property('hardlink_master', bool)

    chunks = PropDict._make_property('chunks', (list, type(None)), 'list or None')
    chunks_healthy = PropDict._make_property('chunks_healthy', (list, type(None)), 'list or None')

    xattrs = PropDict._make_property('xattrs', StableDict)

    deleted = PropDict._make_property('deleted', bool)
    nlink = PropDict._make_property('nlink', int)

    part = PropDict._make_property('part', int)

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


class EncryptedKey(PropDict):
    """
    EncryptedKey abstraction that deals with validation and the low-level details internally:

    A EncryptedKey is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to EncryptedKey(d) and use enc_key.xxx later.

    If a EncryptedKey shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'algorithm', 'iterations', 'salt', 'hash', 'data'}  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    version = PropDict._make_property('version', int)
    algorithm = PropDict._make_property('algorithm', str, encode=str.encode, decode=bytes.decode)
    iterations = PropDict._make_property('iterations', int)
    salt = PropDict._make_property('salt', bytes)
    hash = PropDict._make_property('hash', bytes)
    data = PropDict._make_property('data', bytes)


class Key(PropDict):
    """
    Key abstraction that deals with validation and the low-level details internally:

    A Key is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to Key(d) and use key.xxx later.

    If a Key shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'repository_id', 'enc_key', 'enc_hmac_key', 'id_key', 'chunk_seed',
                  'chunk_permutation', 'tam_required'}  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    version = PropDict._make_property('version', int)
    repository_id = PropDict._make_property('repository_id', bytes)
    enc_key = PropDict._make_property('enc_key', bytes)
    enc_hmac_key = PropDict._make_property('enc_hmac_key', bytes)
    id_key = PropDict._make_property('id_key', bytes)
    chunk_seed = PropDict._make_property('chunk_seed', int)
    chunk_permutation = PropDict._make_property('chunk_permutation', bytes)
    tam_required = PropDict._make_property('tam_required', bool)


def tuple_encode(t):
    """encode a tuple that might contain str items"""
    # we have str, but want to give bytes to msgpack.pack
    return tuple(safe_encode(e) if isinstance(e, str) else e for e in t)


def tuple_decode(t):
    """decode a tuple that might contain bytes items"""
    # we get bytes objects from msgpack.unpack, but want str
    return tuple(safe_decode(e) if isinstance(e, bytes) else e for e in t)


class ArchiveItem(PropDict):
    """
    ArchiveItem abstraction that deals with validation and the low-level details internally:

    An ArchiveItem is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to ArchiveItem(d) and use arch.xxx later.

    If a ArchiveItem shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = ARCHIVE_KEYS  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    version = PropDict._make_property('version', int)
    name = PropDict._make_property('name', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    items = PropDict._make_property('items', list)
    cmdline = PropDict._make_property('cmdline', list)  # list of s-e-str
    hostname = PropDict._make_property('hostname', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    username = PropDict._make_property('username', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    time = PropDict._make_property('time', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    time_end = PropDict._make_property('time_end', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    comment = PropDict._make_property('comment', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    chunker_params = PropDict._make_property('chunker_params', tuple, 'chunker-params tuple', encode=tuple_encode, decode=tuple_decode)
    recreate_cmdline = PropDict._make_property('recreate_cmdline', list)  # list of s-e-str
    # recreate_source_id, recreate_args, recreate_partial_chunks were used in 1.1.0b1 .. b2
    recreate_source_id = PropDict._make_property('recreate_source_id', bytes)
    recreate_args = PropDict._make_property('recreate_args', list)  # list of s-e-str
    recreate_partial_chunks = PropDict._make_property('recreate_partial_chunks', list)  # list of tuples
    size = PropDict._make_property('size', int)
    csize = PropDict._make_property('csize', int)
    nfiles = PropDict._make_property('nfiles', int)
    size_parts = PropDict._make_property('size_parts', int)
    csize_parts = PropDict._make_property('csize_parts', int)
    nfiles_parts = PropDict._make_property('nfiles_parts', int)


class ManifestItem(PropDict):
    """
    ManifestItem abstraction that deals with validation and the low-level details internally:

    A ManifestItem is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to ManifestItem(d) and use manifest.xxx later.

    If a ManifestItem shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'archives', 'timestamp', 'config', 'item_keys', }  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    version = PropDict._make_property('version', int)
    archives = PropDict._make_property('archives', dict)  # name -> dict
    timestamp = PropDict._make_property('timestamp', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    config = PropDict._make_property('config', dict)
    item_keys = PropDict._make_property('item_keys', tuple)

class ItemDiff:
    """
    Comparison of two items from different archives.

    The items may have different paths and still be considered equal (e.g. for renames).
    It does not include extended or time attributes in the comparison.
    """

    def __init__(self, item1, item2, chunk_iterator1, chunk_iterator2, numeric_owner=False, can_compare_chunk_ids=False):
        self._item1 = item1
        self._item2 = item2
        self._numeric_owner = numeric_owner
        self._can_compare_chunk_ids = can_compare_chunk_ids
        self.equal = self._equal(chunk_iterator1, chunk_iterator2)

    def __repr__(self):
        if self.equal:
            return 'equal'

        changes = []

        if self._item1.is_link() or self._item2.is_link():
            changes.append(self._link_string())

        if 'chunks' in self._item1 and 'chunks' in self._item2:
            changes.append(self._content_string())

        if self._item1.is_dir() or self._item2.is_dir():
            changes.append(self._dir_string())

        if not (self._item1.get('deleted') or self._item2.get('deleted')):
            changes.append(self._owner_string())
            changes.append(self._mode_string())

        return ' '.join((x for x in changes if x))

    def _equal(self, chunk_iterator1, chunk_iterator2):
        # if both are deleted, there is nothing at path regardless of what was deleted
        if self._item1.get('deleted') and self._item2.get('deleted'):
            return True

        attr_list = ['deleted', 'mode', 'source']
        attr_list += ['uid', 'gid'] if self._numeric_owner else ['user', 'group']
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

    def _link_string(self):
        if self._item1.get('deleted'):
            return 'added link'
        if self._item2.get('deleted'):
            return 'removed link'
        if 'source' in self._item1 and 'source' in self._item2 and self._item1.source != self._item2.source:
            return 'changed link'

    def _content_string(self):
        if self._item1.get('deleted'):
            return ('added {:>13}'.format(format_file_size(self._item2.get_size())))
        if self._item2.get('deleted'):
            return ('removed {:>11}'.format(format_file_size(self._item1.get_size())))
        if not self._can_compare_chunk_ids:
            return 'modified'
        chunk_ids1 = {c.id for c in self._item1.chunks}
        chunk_ids2 = {c.id for c in self._item2.chunks}
        added_ids = chunk_ids2 - chunk_ids1
        removed_ids = chunk_ids1 - chunk_ids2
        added = self._item2.get_size(consider_ids=added_ids)
        removed = self._item1.get_size(consider_ids=removed_ids)
        return ('{:>9} {:>9}'.format(format_file_size(added, precision=1, sign=True),
                                     format_file_size(-removed, precision=1, sign=True)))

    def _dir_string(self):
        if self._item2.get('deleted') and not self._item1.get('deleted'):
            return 'removed directory'
        if self._item1.get('deleted') and not self._item2.get('deleted'):
            return 'added directory'

    def _owner_string(self):
        u_attr, g_attr = ('uid', 'gid') if self._numeric_owner else ('user', 'group')
        u1, g1 = self._item1.get(u_attr), self._item1.get(g_attr)
        u2, g2 = self._item2.get(u_attr), self._item2.get(g_attr)
        if (u1, g1) != (u2, g2):
            return '[{}:{} -> {}:{}]'.format(u1, g1, u2, g2)

    def _mode_string(self):
        if 'mode' in self._item1 and 'mode' in self._item2 and self._item1.mode != self._item2.mode:
            return '[{} -> {}]'.format(stat.filemode(self._item1.mode), stat.filemode(self._item2.mode))

    def _content_equal(self, chunk_iterator1, chunk_iterator2):
        if self._can_compare_chunk_ids:
            return self._item1.chunks == self._item2.chunks
        if self._item1.get_size() != self._item2.get_size():
            return False
        return ItemDiff._chunk_content_equal(chunk_iterator1, chunk_iterator2)

    @staticmethod
    def _chunk_content_equal(chunks1, chunks2):
        """
        Compare chunk content and return True if they are identical.

        The chunks must be given as chunk iterators (like returned by :meth:`.DownloadPipeline.fetch_many`).
        """

        end = object()
        alen = ai = 0
        blen = bi = 0
        while True:
            if not alen - ai:
                a = next(chunks1, end)
                if a is end:
                    return not blen - bi and next(chunks2, end) is end
                a = memoryview(a)
                alen = len(a)
                ai = 0
            if not blen - bi:
                b = next(chunks2, end)
                if b is end:
                    return not alen - ai and next(chunks1, end) is end
                b = memoryview(b)
                blen = len(b)
                bi = 0
            slicelen = min(alen - ai, blen - bi)
            if a[ai:ai + slicelen] != b[bi:bi + slicelen]:
                return False
            ai += slicelen
            bi += slicelen
