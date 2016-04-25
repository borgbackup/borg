from .constants import ITEM_KEYS
from .helpers import safe_encode, safe_decode, StableDict

# we want str keys for this code
ITEM_KEYS = set(key.decode() for key in ITEM_KEYS)


class Item:
    """
    Item abstraction that deals with validation and the low-level details internally:

    - msgpack gives us a dict with bytes-typed keys - but we do not want to have the ugly
      bytes-typed keys and the hard-to-type dict item access all over the place (like: item[b'keyname']),
      so we define properties (and use it like: item.keyname)
    - msgpack gives us byte-typed values for stuff that should be str, we need to decode/encode them here.
    - we want to be safe against typos in keys and badly typed values, so we check them.

    Items are created either from msgpack unpacker output, from another dict or
    built step-by-step by setting attributes.

    If an Item shall be serialized, give as_dict() method output to msgpack packer.
    """

    VALID_KEYS = ITEM_KEYS

    def __init__(self, data_dict=None, **kw):
        if data_dict is None:
            data = kw
        elif not isinstance(data_dict, dict):
            raise TypeError("data_dict must be dict")
        else:
            data = data_dict
        # internally, we want an dict with only str-typed keys
        _dict = {}
        for k, v in data.items():
            if isinstance(k, bytes):
                k = k.decode()
            elif not isinstance(k, str):
                raise TypeError("dict keys must be str or bytes, not %r" % k)
            _dict[k] = v
        unknown_keys = set(_dict) - self.VALID_KEYS
        if unknown_keys:
            raise ValueError("dict contains unknown keys %s" % ','.join(unknown_keys))
        self._dict = _dict

    def as_dict(self):
        """return the internal dictionary"""
        return self._dict  # XXX use StableDict?

    def _check_key(self, key):
        """make sure key is of type str and known"""
        if not isinstance(key, str):
            raise TypeError("key must be str")
        if key not in self.VALID_KEYS:
            raise ValueError("key '%s' unknown" % key)
        return key

    def __contains__(self, key):
        """do we have this key?"""
        return self._check_key(key) in self._dict

    def get(self, key, default=None):
        """get value for key, return default if key does not exist"""
        return getattr(self, self._check_key(key), default)

    def _make_property(key, value_type, value_type_name=None, encode=None, decode=None):
        """return a property that deals with self._dict[key]:

           - sets the value (checking type and optionally encoding it)
           - gets the value (optionally decoding it)
           - deletes the entry from the internal dict
           - creates reasonable docstring and exceptions / exception messages
        """
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

    # properties statically defined, so that IDEs can know their names:

    path = _make_property('path', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    source = _make_property('source', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    user = _make_property('user', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    group = _make_property('group', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    acl_access = _make_property('acl_access', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    acl_default = _make_property('acl_default', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    acl_extended = _make_property('acl_extended', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)
    acl_nfs4 = _make_property('acl_nfs4', str, 'surrogate-escaped str', encode=safe_encode, decode=safe_decode)

    mode = _make_property('mode', int)
    uid = _make_property('uid', int)
    gid = _make_property('gid', int)
    atime = _make_property('atime', int)
    ctime = _make_property('ctime', int)
    mtime = _make_property('mtime', int)
    rdev = _make_property('rdev', int)
    bsdflags = _make_property('bsdflags', int)

    hardlink_master = _make_property('hardlink_master', bool)

    chunks = _make_property('chunks', list)

    xattrs = _make_property('xattrs', StableDict)
