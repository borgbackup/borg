#include <Python/Python.h>
#include <Python/structmember.h>

static unsigned long int
checksum(const unsigned char *data, int len, unsigned long int sum)
{
    unsigned long int s1, s2, i;
    s1 = sum & 0xffff;
    s2 = sum >> 16;
    for(i=0; i < len; i++)
    {
        s1 += data[i] + 1;
        s2 += s1;
    }
    return ((s2 & 0xffff) << 16) | (s1 & 0xffff);
}

static unsigned long int
roll_checksum(unsigned long int sum, unsigned char remove, unsigned char add, int len)
{
    unsigned long int s1, s2;
    s1 = sum & 0xffff;
    s2 = sum >> 16;
    s1 -= remove - add;
    s2 -= len * (remove + 1) - s1;
    return ((s2 & 0xffff) << 16) | (s1 & 0xffff);
}

typedef struct {
    PyObject_HEAD
    int chunk_size, i, full_sum, done, buf_size, data_len;
    PyObject *chunks, *fd, *extra;
    unsigned long sum;
    unsigned char *data, add, remove;
} ChunkifyIter;

static PyObject*
ChunkifyIter_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

static void
ChunkifyIter_dealloc(PyObject *self)
{
    ChunkifyIter *c = (ChunkifyIter *)self;
    Py_DECREF(c->fd);
    Py_XDECREF(c->chunks);
    free(c->data);
    self->ob_type->tp_free(self);
}

static PyObject*
ChunkifyIter_iternext(PyObject *self)
{
    ChunkifyIter *c = (ChunkifyIter *)self;
    PyObject *pysum;
    int o = 0;
    if(c->done)
    {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
    if(c->extra)
    {
        c->done = 1;
	Py_INCREF(c->extra);
        return c->extra;
    }
    for(;;)
    {
        if(c->i > c->buf_size - c->chunk_size)
        {
            memmove(c->data, c->data + c->i - o, c->data_len - c->i + o);
            c->data_len -= c->i - o;
            c->i = o;
        }
        if(c->data_len - c->i < c->chunk_size)
        {
            PyObject *data = PyObject_CallMethod(c->fd, "read", "i", c->buf_size - c->data_len);
            int n = PyString_Size(data);
            memcpy(c->data + c->data_len, PyString_AsString(data), n);
            c->data_len += n;
            Py_DECREF(data);
        }
        if(c->i == c->data_len)
        {
            PyErr_SetNone(PyExc_StopIteration);
            return NULL;
        }
        if(c->data_len - c->i < c->chunk_size) /* EOF ? */
        {
            if(o == 1)
            {
                c->done = 1;
                return PyString_FromStringAndSize((char *)(c->data + c->i - 1), c->data_len - c->i + 1);
            }
            else if(o > 1)
            {
                c->extra = PyString_FromStringAndSize((char *)(c->data + c->i - 1), c->chunk_size);
                return PyString_FromStringAndSize((char *)(c->data + c->i - o), o - 1);
            }
            else
            {
                c->done = 1;
                return PyString_FromStringAndSize((char *)(c->data + c->i), c->data_len - c->i);
            }
        }
        if(o == c->chunk_size)
        {
            return PyString_FromStringAndSize((char *)(c->data + c->i - c->chunk_size), c->chunk_size);
        }
        if(c->full_sum || c->i + c->chunk_size > c->data_len)
        {
            c->full_sum = 0;
            c->sum = checksum(c->data + c->i, c->chunk_size, 0);
        }
        else
        {
            c->sum = roll_checksum(c->sum, c->remove, c->data[c->i + c->chunk_size - 1], c->chunk_size);
        }
        c->remove = c->data[c->i];
        pysum = PyInt_FromLong(c->sum);
        if(PySequence_Contains(c->chunks, pysum) == 1)
        {
            Py_DECREF(pysum);
            c->full_sum = 1;
            if(o > 0)
            {
                return PyString_FromStringAndSize((char *)(c->data + c->i - o), o);
            }
            else
            {
                c->i += c->chunk_size;
                return PyString_FromStringAndSize((char *)(c->data + c->i - c->chunk_size), c->chunk_size);
            }
        }
        Py_DECREF(pysum);
        o++;
        c->i++;
    }
    PyErr_SetNone(PyExc_StopIteration);
    return NULL;
}

static PyTypeObject ChunkifyIterType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "_chunkifier._ChunkifyIter",       /*tp_name*/
    sizeof(ChunkifyIter),       /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    ChunkifyIter_dealloc,      /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
      /* tp_flags: Py_TPFLAGS_HAVE_ITER tells python to
         use tp_iter and tp_iternext fields. */
    "",           /* tp_doc */
    0,  /* tp_traverse */
    0,  /* tp_clear */
    0,  /* tp_richcompare */
    0,  /* tp_weaklistoffset */
    ChunkifyIter_iter,  /* tp_iter: __iter__() method */
    ChunkifyIter_iternext  /* tp_iternext: next() method */
};

static PyObject *
chunkify(PyObject *self, PyObject *args)
{
    PyObject *fd, *chunks;
    long int chunk_size;
    ChunkifyIter *c;

    if (!PyArg_ParseTuple(args, "OiO", &fd, &chunk_size, &chunks))
    {
        return NULL;
    }
    if (!(c = PyObject_New(ChunkifyIter, &ChunkifyIterType)))
    {
        return NULL;
    }
    PyObject_Init((PyObject *)c, &ChunkifyIterType);
    c->buf_size = chunk_size * 10;
    c->data = malloc(c->buf_size);
    c->data_len = 0;
    c->i = 0;
    c->full_sum = 1;
    c->done = 0;
    c->extra = NULL;
    c->fd = fd;
    c->chunk_size = chunk_size;
    c->chunks = chunks;
    Py_INCREF(fd);
    Py_INCREF(chunks);
    return (PyObject *)c;
}

static PyObject *
py_checksum(PyObject *self, PyObject *args)
{
    PyObject *data;
    unsigned long int sum = 0;
    if(!PyArg_ParseTuple(args, "O|k", &data, &sum))  return NULL;
    if(!PyString_Check(data))
    {
        PyErr_SetNone(PyExc_TypeError);
        return NULL;
    }
    return PyInt_FromLong(checksum((unsigned char *)PyString_AsString(data),
                                   PyString_Size(data), sum));
}

static PyObject *
py_roll_checksum(PyObject *self, PyObject *args)
{
    unsigned long int sum = 0, len, a, r;
    PyObject *add, *remove;
    if (!PyArg_ParseTuple(args, "kOOk", &sum, &remove, &add, &len))  return NULL;
    if(!PyString_Check(remove) || !PyString_Check(add) || 
        PyString_Size(remove) != 1 || PyString_Size(add) != 1)
    {
        PyErr_SetNone(PyExc_TypeError);
        return NULL;
    }
    a = *((const unsigned char *)PyString_AsString(add));
    r = *((const unsigned char *)PyString_AsString(remove));
    return PyInt_FromLong(roll_checksum(sum, r, a, len));
}


static PyMethodDef ChunkifierMethods[] = {
    {"chunkify",  chunkify, METH_VARARGS, ""},
    {"checksum",  py_checksum, METH_VARARGS, ""},
    {"roll_checksum",  py_roll_checksum, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
init_speedups(void)
{
  PyObject* m;

  ChunkifyIterType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&ChunkifyIterType) < 0)  return;

  m = Py_InitModule("_speedups", ChunkifierMethods);

  Py_INCREF(&ChunkifyIterType);
  PyModule_AddObject(m, "_ChunkifyIter", (PyObject *)&ChunkifyIterType);
}
