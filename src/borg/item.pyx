import stat
from collections import namedtuple

from .constants import ITEM_KEYS, ARCHIVE_KEYS
from .helpers import StableDict
from .helpers import format_file_size
from .helpers.msgpack import timestamp_to_int, int_to_timestamp, Timestamp


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
    """make sure we have a tuple of str"""
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
            if not isinstance(value, value_type):
                raise TypeError(type_error_msg)
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


ChunkListEntry = namedtuple('ChunkListEntry', 'id size')

class Item(PropDict):
    """
    Item abstraction that deals with validation and the low-level details internally:

    Items are created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to Item(internal_dict=d) and use item.key_name later.

    If an Item shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = ITEM_KEYS | {'deleted', 'nlink', }  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    # properties statically defined, so that IDEs can know their names:

    path = PropDict._make_property('path', str, 'surrogate-escaped str')
    source = PropDict._make_property('source', str, 'surrogate-escaped str')
    user = PropDict._make_property('user', str, 'surrogate-escaped str')
    group = PropDict._make_property('group', str, 'surrogate-escaped str')

    acl_access = PropDict._make_property('acl_access', bytes)
    acl_default = PropDict._make_property('acl_default', bytes)
    acl_extended = PropDict._make_property('acl_extended', bytes)
    acl_nfs4 = PropDict._make_property('acl_nfs4', bytes)

    mode = PropDict._make_property('mode', int)
    uid = PropDict._make_property('uid', int)
    gid = PropDict._make_property('gid', int)
    rdev = PropDict._make_property('rdev', int)
    bsdflags = PropDict._make_property('bsdflags', int)

    atime = PropDict._make_property('atime', int, 'int (ns)', encode=int_to_timestamp, decode=timestamp_to_int)
    ctime = PropDict._make_property('ctime', int, 'int (ns)', encode=int_to_timestamp, decode=timestamp_to_int)
    mtime = PropDict._make_property('mtime', int, 'int (ns)', encode=int_to_timestamp, decode=timestamp_to_int)
    birthtime = PropDict._make_property('birthtime', int, 'int (ns)', encode=int_to_timestamp, decode=timestamp_to_int)

    # size is only present for items with a chunk list and then it is sum(chunk_sizes)
    size = PropDict._make_property('size', int)

    hlid = PropDict._make_property('hlid', bytes)  # hard link id: same value means same hard link.
    hardlink_master = PropDict._make_property('hardlink_master', bool)  # legacy

    chunks = PropDict._make_property('chunks', list, 'list')
    chunks_healthy = PropDict._make_property('chunks_healthy', list, 'list')

    xattrs = PropDict._make_property('xattrs', StableDict)

    deleted = PropDict._make_property('deleted', bool)
    nlink = PropDict._make_property('nlink', int)

    part = PropDict._make_property('part', int)

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
                return len(self.source)
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
            if k in ('path', 'source', 'user', 'group'):
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


class EncryptedKey(PropDict):
    """
    EncryptedKey abstraction that deals with validation and the low-level details internally:

    A EncryptedKey is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to EncryptedKey(d) and use enc_key.xxx later.

    If a EncryptedKey shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'algorithm', 'iterations', 'salt', 'hash', 'data',
                  'argon2_time_cost', 'argon2_memory_cost', 'argon2_parallelism', 'argon2_type'}

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    version = PropDict._make_property('version', int)
    algorithm = PropDict._make_property('algorithm', str)
    iterations = PropDict._make_property('iterations', int)
    salt = PropDict._make_property('salt', bytes)
    hash = PropDict._make_property('hash', bytes)
    data = PropDict._make_property('data', bytes)
    argon2_time_cost = PropDict._make_property('argon2_time_cost', int)
    argon2_memory_cost = PropDict._make_property('argon2_memory_cost', int)
    argon2_parallelism = PropDict._make_property('argon2_parallelism', int)
    argon2_type = PropDict._make_property('argon2_type', str)

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


class Key(PropDict):
    """
    Key abstraction that deals with validation and the low-level details internally:

    A Key is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to Key(d) and use key.xxx later.

    If a Key shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'repository_id', 'crypt_key', 'id_key', 'chunk_seed', 'tam_required'}  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    version = PropDict._make_property('version', int)
    repository_id = PropDict._make_property('repository_id', bytes)
    crypt_key = PropDict._make_property('crypt_key', bytes)
    id_key = PropDict._make_property('id_key', bytes)
    chunk_seed = PropDict._make_property('chunk_seed', int)
    tam_required = PropDict._make_property('tam_required', bool)

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

class ArchiveItem(PropDict):
    """
    ArchiveItem abstraction that deals with validation and the low-level details internally:

    An ArchiveItem is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to ArchiveItem(d) and use arch.xxx later.

    If a ArchiveItem shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = ARCHIVE_KEYS  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    version = PropDict._make_property('version', int)
    name = PropDict._make_property('name', str, 'surrogate-escaped str')
    items = PropDict._make_property('items', list)  # list of chunk ids of item metadata stream (only in memory)
    item_ptrs = PropDict._make_property('item_ptrs', list)  # list of blocks with list of chunk ids of ims, arch v2
    cmdline = PropDict._make_property('cmdline', list)  # list of s-e-str
    hostname = PropDict._make_property('hostname', str, 'surrogate-escaped str')
    username = PropDict._make_property('username', str, 'surrogate-escaped str')
    time = PropDict._make_property('time', str)
    time_end = PropDict._make_property('time_end', str)
    comment = PropDict._make_property('comment', str, 'surrogate-escaped str')
    chunker_params = PropDict._make_property('chunker_params', tuple)
    recreate_cmdline = PropDict._make_property('recreate_cmdline', list)  # list of s-e-str
    # recreate_source_id, recreate_args, recreate_partial_chunks were used in 1.1.0b1 .. b2
    recreate_source_id = PropDict._make_property('recreate_source_id', bytes)
    recreate_args = PropDict._make_property('recreate_args', list)  # list of s-e-str
    recreate_partial_chunks = PropDict._make_property('recreate_partial_chunks', list)  # list of tuples
    size = PropDict._make_property('size', int)
    nfiles = PropDict._make_property('nfiles', int)
    size_parts = PropDict._make_property('size_parts', int)
    nfiles_parts = PropDict._make_property('nfiles_parts', int)

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
            if k in ('cmdline', 'recreate_cmdline'):
                v = fix_list_of_str(v)
            if k == 'items':  # legacy
                v = fix_list_of_bytes(v)
            if k == 'item_ptrs':
                v = fix_list_of_bytes(v)
            self._dict[k] = v


class ManifestItem(PropDict):
    """
    ManifestItem abstraction that deals with validation and the low-level details internally:

    A ManifestItem is created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack unpacker gives us a dict, just give it to ManifestItem(d) and use manifest.xxx later.

    If a ManifestItem shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = {'version', 'archives', 'timestamp', 'config', 'item_keys', }  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    version = PropDict._make_property('version', int)
    archives = PropDict._make_property('archives', dict, 'dict of str -> dict')  # name -> dict
    timestamp = PropDict._make_property('timestamp', str)
    config = PropDict._make_property('config', dict)
    item_keys = PropDict._make_property('item_keys', tuple, 'tuple of str')

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
            changes.append(self._presence_diff('directory'))

        if self._item1.is_blk() or self._item2.is_blk():
            changes.append(self._presence_diff('blkdev'))

        if self._item1.is_chr() or self._item2.is_chr():
            changes.append(self._presence_diff('chrdev'))

        if self._item1.is_fifo() or self._item2.is_fifo():
            changes.append(self._presence_diff('fifo'))

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

    def _presence_diff(self, item_type):
        if not self._item1.get('deleted') and self._item2.get('deleted'):
            chg = 'removed ' + item_type
            return ({"type": chg}, chg)
        if self._item1.get('deleted') and not self._item2.get('deleted'):
            chg = 'added ' + item_type
            return ({"type": chg}, chg)

    def _link_diff(self):
        pd = self._presence_diff('link')
        if pd is not None:
            return pd
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
