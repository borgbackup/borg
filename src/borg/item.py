from .constants import ITEM_KEYS
from .helpers import safe_encode, safe_decode
from .helpers import bigint_to_int, int_to_bigint
from .helpers import StableDict


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
    """
    VALID_KEYS = None  # override with <set of str> in child class

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    def __init__(self, data_dict=None, internal_dict=None, **kw):
        if data_dict is None:
            data = kw
        elif not isinstance(data_dict, dict):
            raise TypeError("data_dict must be dict")
        else:
            data = data_dict
        self._dict = {}
        self.update_internal(internal_dict or {})
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


class Item(PropDict):
    """
    Item abstraction that deals with validation and the low-level details internally:

    Items are created either from msgpack unpacker output, from another dict, from kwargs or
    built step-by-step by setting attributes.

    msgpack gives us a dict with bytes-typed keys, just give it to Item(d) and use item.key_name later.
    msgpack gives us byte-typed values for stuff that should be str, we automatically decode when getting
    such a property and encode when setting it.

    If an Item shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = ITEM_KEYS | {'deleted'}  # str-typed keys

    __slots__ = ("_dict", )  # avoid setting attributes not supported by properties

    # properties statically defined, so that IDEs can know their names:

    path = PropDict._make_property('path', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    source = PropDict._make_property('source', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    user = PropDict._make_property('user', (str, type(None)), 'surrogate-escaped str or None', encode=safe_encode, decode=safe_decode)
    group = PropDict._make_property('group', (str, type(None)), 'surrogate-escaped str or None', encode=safe_encode, decode=safe_decode)

    acl_access = PropDict._make_property('acl_access', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    acl_default = PropDict._make_property('acl_default', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    acl_extended = PropDict._make_property('acl_extended', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    acl_nfs4 = PropDict._make_property('acl_nfs4', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)

    mode = PropDict._make_property('mode', int)
    uid = PropDict._make_property('uid', int)
    gid = PropDict._make_property('gid', int)
    rdev = PropDict._make_property('rdev', int)
    bsdflags = PropDict._make_property('bsdflags', int)

    atime = PropDict._make_property('atime', int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)
    ctime = PropDict._make_property('ctime', int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)
    mtime = PropDict._make_property('mtime', int, 'bigint', encode=int_to_bigint, decode=bigint_to_int)

    hardlink_master = PropDict._make_property('hardlink_master', bool)

    chunks = PropDict._make_property('chunks', (list, type(None)), 'list or None')

    xattrs = PropDict._make_property('xattrs', StableDict)

    deleted = PropDict._make_property('deleted', bool)
