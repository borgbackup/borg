# coding: utf-8
#cython: embedsignature=True, c_string_encoding=ascii, language_level=2

from cpython cimport *
from cpython.version cimport PY_MAJOR_VERSION
from cpython.exc cimport PyErr_WarnEx

from .exceptions import PackValueError, PackOverflowError
from . import ExtType


cdef extern from "Python.h":

    int PyMemoryView_Check(object obj)
    int PyByteArray_Check(object obj)
    int PyByteArray_CheckExact(object obj)
    char* PyUnicode_AsUTF8AndSize(object obj, Py_ssize_t *l) except NULL


cdef extern from "pack.h":
    struct msgpack_packer:
        char* buf
        size_t length
        size_t buf_size
        bint use_bin_type

    int msgpack_pack_int(msgpack_packer* pk, int d)
    int msgpack_pack_nil(msgpack_packer* pk)
    int msgpack_pack_true(msgpack_packer* pk)
    int msgpack_pack_false(msgpack_packer* pk)
    int msgpack_pack_long(msgpack_packer* pk, long d)
    int msgpack_pack_long_long(msgpack_packer* pk, long long d)
    int msgpack_pack_unsigned_long_long(msgpack_packer* pk, unsigned long long d)
    int msgpack_pack_float(msgpack_packer* pk, float d)
    int msgpack_pack_double(msgpack_packer* pk, double d)
    int msgpack_pack_array(msgpack_packer* pk, size_t l)
    int msgpack_pack_map(msgpack_packer* pk, size_t l)
    int msgpack_pack_raw(msgpack_packer* pk, size_t l)
    int msgpack_pack_bin(msgpack_packer* pk, size_t l)
    int msgpack_pack_raw_body(msgpack_packer* pk, char* body, size_t l)
    int msgpack_pack_ext(msgpack_packer* pk, char typecode, size_t l)
    int msgpack_pack_unicode(msgpack_packer* pk, object o, long long limit)

cdef int DEFAULT_RECURSE_LIMIT=511
cdef long long ITEM_LIMIT = (2**32)-1


cdef inline int PyBytesLike_Check(object o):
    return PyBytes_Check(o) or PyByteArray_Check(o)


cdef inline int PyBytesLike_CheckExact(object o):
    return PyBytes_CheckExact(o) or PyByteArray_CheckExact(o)


cdef class Packer(object):
    """
    MessagePack Packer

    usage::

        packer = Packer()
        astream.write(packer.pack(a))
        astream.write(packer.pack(b))

    Packer's constructor has some keyword arguments:

    :param callable default:
        Convert user type to builtin type that Packer supports.
        See also simplejson's document.

    :param bool use_single_float:
        Use single precision float type for float. (default: False)

    :param bool autoreset:
        Reset buffer after each pack and return its content as `bytes`. (default: True).
        If set this to false, use `bytes()` to get content and `.reset()` to clear buffer.

    :param bool use_bin_type:
        Use bin type introduced in msgpack spec 2.0 for bytes.
        It also enables str8 type for unicode.
        Current default value is false, but it will be changed to true
        in future version.  You should specify it explicitly.

    :param bool strict_types:
        If set to true, types will be checked to be exact. Derived classes
        from serializeable types will not be serialized and will be
        treated as unsupported type and forwarded to default.
        Additionally tuples will not be serialized as lists.
        This is useful when trying to implement accurate serialization
        for python types.

    :param str unicode_errors:
        Error handler for encoding unicode. (default: 'strict')

    :param str encoding:
        (deprecated) Convert unicode to bytes with this encoding. (default: 'utf-8')
    """
    cdef msgpack_packer pk
    cdef object _default
    cdef object _bencoding
    cdef object _berrors
    cdef const char *encoding
    cdef const char *unicode_errors
    cdef bint strict_types
    cdef bool use_float
    cdef bint autoreset

    def __cinit__(self):
        cdef int buf_size = 1024*1024
        self.pk.buf = <char*> PyMem_Malloc(buf_size)
        if self.pk.buf == NULL:
            raise MemoryError("Unable to allocate internal buffer.")
        self.pk.buf_size = buf_size
        self.pk.length = 0

    def __init__(self, default=None, encoding=None, unicode_errors=None,
                 bint use_single_float=False, bint autoreset=True, bint use_bin_type=False,
                 bint strict_types=False):
        if encoding is not None:
            PyErr_WarnEx(PendingDeprecationWarning, "encoding is deprecated.", 1)
        self.use_float = use_single_float
        self.strict_types = strict_types
        self.autoreset = autoreset
        self.pk.use_bin_type = use_bin_type
        if default is not None:
            if not PyCallable_Check(default):
                raise TypeError("default must be a callable.")
        self._default = default

        self._bencoding = encoding
        if encoding is None:
            if PY_MAJOR_VERSION < 3:
                self.encoding = 'utf-8'
            else:
                self.encoding = NULL
        else:
            self.encoding = self._bencoding

        self._berrors = unicode_errors
        if unicode_errors is None:
            self.unicode_errors = NULL
        else:
            self.unicode_errors = self._berrors

    def __dealloc__(self):
        PyMem_Free(self.pk.buf)
        self.pk.buf = NULL

    cdef int _pack(self, object o, int nest_limit=DEFAULT_RECURSE_LIMIT) except -1:
        cdef long long llval
        cdef unsigned long long ullval
        cdef long longval
        cdef float fval
        cdef double dval
        cdef char* rawval
        cdef int ret
        cdef dict d
        cdef Py_ssize_t L
        cdef int default_used = 0
        cdef bint strict_types = self.strict_types
        cdef Py_buffer view

        if nest_limit < 0:
            raise PackValueError("recursion limit exceeded.")

        while True:
            if o is None:
                ret = msgpack_pack_nil(&self.pk)
            elif PyBool_Check(o) if strict_types else isinstance(o, bool):
                if o:
                    ret = msgpack_pack_true(&self.pk)
                else:
                    ret = msgpack_pack_false(&self.pk)
            elif PyLong_CheckExact(o) if strict_types else PyLong_Check(o):
                # PyInt_Check(long) is True for Python 3.
                # So we should test long before int.
                try:
                    if o > 0:
                        ullval = o
                        ret = msgpack_pack_unsigned_long_long(&self.pk, ullval)
                    else:
                        llval = o
                        ret = msgpack_pack_long_long(&self.pk, llval)
                except OverflowError as oe:
                    if not default_used and self._default is not None:
                        o = self._default(o)
                        default_used = True
                        continue
                    else:
                        raise PackOverflowError("Integer value out of range")
            elif PyInt_CheckExact(o) if strict_types else PyInt_Check(o):
                longval = o
                ret = msgpack_pack_long(&self.pk, longval)
            elif PyFloat_CheckExact(o) if strict_types else PyFloat_Check(o):
                if self.use_float:
                   fval = o
                   ret = msgpack_pack_float(&self.pk, fval)
                else:
                   dval = o
                   ret = msgpack_pack_double(&self.pk, dval)
            elif PyBytesLike_CheckExact(o) if strict_types else PyBytesLike_Check(o):
                L = len(o)
                if L > ITEM_LIMIT:
                    raise PackValueError("%s is too large" % type(o).__name__)
                rawval = o
                ret = msgpack_pack_bin(&self.pk, L)
                if ret == 0:
                    ret = msgpack_pack_raw_body(&self.pk, rawval, L)
            elif PyUnicode_CheckExact(o) if strict_types else PyUnicode_Check(o):
                if self.encoding == NULL and self.unicode_errors == NULL:
                    ret = msgpack_pack_unicode(&self.pk, o, ITEM_LIMIT);
                    if ret == -2:
                        raise PackValueError("unicode string is too large")
                else:
                    o = PyUnicode_AsEncodedString(o, self.encoding, self.unicode_errors)
                    L = len(o)
                    if L > ITEM_LIMIT:
                        raise PackValueError("unicode string is too large")
                    ret = msgpack_pack_raw(&self.pk, L)
                    if ret == 0:
                        rawval = o
                        ret = msgpack_pack_raw_body(&self.pk, rawval, L)
            elif PyDict_CheckExact(o):
                d = <dict>o
                L = len(d)
                if L > ITEM_LIMIT:
                    raise PackValueError("dict is too large")
                ret = msgpack_pack_map(&self.pk, L)
                if ret == 0:
                    for k, v in d.iteritems():
                        ret = self._pack(k, nest_limit-1)
                        if ret != 0: break
                        ret = self._pack(v, nest_limit-1)
                        if ret != 0: break
            elif not strict_types and PyDict_Check(o):
                L = len(o)
                if L > ITEM_LIMIT:
                    raise PackValueError("dict is too large")
                ret = msgpack_pack_map(&self.pk, L)
                if ret == 0:
                    for k, v in o.items():
                        ret = self._pack(k, nest_limit-1)
                        if ret != 0: break
                        ret = self._pack(v, nest_limit-1)
                        if ret != 0: break
            elif type(o) is ExtType if strict_types else isinstance(o, ExtType):
                # This should be before Tuple because ExtType is namedtuple.
                longval = o.code
                rawval = o.data
                L = len(o.data)
                if L > ITEM_LIMIT:
                    raise PackValueError("EXT data is too large")
                ret = msgpack_pack_ext(&self.pk, longval, L)
                ret = msgpack_pack_raw_body(&self.pk, rawval, L)
            elif PyList_CheckExact(o) if strict_types else (PyTuple_Check(o) or PyList_Check(o)):
                L = len(o)
                if L > ITEM_LIMIT:
                    raise PackValueError("list is too large")
                ret = msgpack_pack_array(&self.pk, L)
                if ret == 0:
                    for v in o:
                        ret = self._pack(v, nest_limit-1)
                        if ret != 0: break
            elif PyMemoryView_Check(o):
                if PyObject_GetBuffer(o, &view, PyBUF_SIMPLE) != 0:
                    raise PackValueError("could not get buffer for memoryview")
                L = view.len
                if L > ITEM_LIMIT:
                    PyBuffer_Release(&view);
                    raise PackValueError("memoryview is too large")
                ret = msgpack_pack_bin(&self.pk, L)
                if ret == 0:
                    ret = msgpack_pack_raw_body(&self.pk, <char*>view.buf, L)
                PyBuffer_Release(&view);
            elif not default_used and self._default:
                o = self._default(o)
                default_used = 1
                continue
            else:
                raise TypeError("can't serialize %r" % (o,))
            return ret

    cpdef pack(self, object obj):
        cdef int ret
        try:
            ret = self._pack(obj, DEFAULT_RECURSE_LIMIT)
        except:
            self.pk.length = 0
            raise
        if ret:  # should not happen.
            raise RuntimeError("internal error")
        if self.autoreset:
            buf = PyBytes_FromStringAndSize(self.pk.buf, self.pk.length)
            self.pk.length = 0
            return buf

    def pack_ext_type(self, typecode, data):
        msgpack_pack_ext(&self.pk, typecode, len(data))
        msgpack_pack_raw_body(&self.pk, data, len(data))

    def pack_array_header(self, long long size):
        if size > ITEM_LIMIT:
            raise PackValueError
        cdef int ret = msgpack_pack_array(&self.pk, size)
        if ret == -1:
            raise MemoryError
        elif ret:  # should not happen
            raise TypeError
        if self.autoreset:
            buf = PyBytes_FromStringAndSize(self.pk.buf, self.pk.length)
            self.pk.length = 0
            return buf

    def pack_map_header(self, long long size):
        if size > ITEM_LIMIT:
            raise PackValueError
        cdef int ret = msgpack_pack_map(&self.pk, size)
        if ret == -1:
            raise MemoryError
        elif ret:  # should not happen
            raise TypeError
        if self.autoreset:
            buf = PyBytes_FromStringAndSize(self.pk.buf, self.pk.length)
            self.pk.length = 0
            return buf

    def pack_map_pairs(self, object pairs):
        """
        Pack *pairs* as msgpack map type.

        *pairs* should be a sequence of pairs.
        (`len(pairs)` and `for k, v in pairs:` should be supported.)
        """
        cdef int ret = msgpack_pack_map(&self.pk, len(pairs))
        if ret == 0:
            for k, v in pairs:
                ret = self._pack(k)
                if ret != 0: break
                ret = self._pack(v)
                if ret != 0: break
        if ret == -1:
            raise MemoryError
        elif ret:  # should not happen
            raise TypeError
        if self.autoreset:
            buf = PyBytes_FromStringAndSize(self.pk.buf, self.pk.length)
            self.pk.length = 0
            return buf

    def reset(self):
        """Clear internal buffer."""
        self.pk.length = 0

    def bytes(self):
        """Return buffer content."""
        return PyBytes_FromStringAndSize(self.pk.buf, self.pk.length)
