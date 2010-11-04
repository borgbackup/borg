#include <Python.h>
#include <structmember.h>

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define ABS(X) ((X) < 0 ? (-(X)) : (X))

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
    int chunk_size, window_size, i, last, eof, done, buf_size, data_len, seed;
    PyObject *chunks, *fd;
    unsigned long int sum;
    unsigned char *data, add, remove;
} ChunkifyIter;

static PyObject*
ChunkifyIter_iter(PyObject *self)
{
    ChunkifyIter *c = (ChunkifyIter *)self;
    c->data_len = 0;
    c->done = 0;
    c->eof = 0;
    c->i = 0;
    c->sum = 0;
    c->last = 0;
    Py_INCREF(self);
    return self;
}

static void
ChunkifyIter_dealloc(PyObject *self)
{
    ChunkifyIter *c = (ChunkifyIter *)self;
    Py_DECREF(c->fd);
    free(c->data);
    self->ob_type->tp_free(self);
}

static PyObject*
ChunkifyIter_iternext(PyObject *self)
{
    ChunkifyIter *c = (ChunkifyIter *)self;
    int initial = c->window_size;

    if(c->done)
    {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
    for(;;)
    {
        if(c->i == c->buf_size)
        {
            int diff = c->last + 1 - c->window_size;
            assert(diff >= 0);
            memmove(c->data, c->data + diff, c->buf_size - diff);
            c->i -= diff;
            c->last -= diff;
            c->data_len -= diff;
            assert(c->i >= 0);
            assert(c->last >= -1);
            assert(c->data_len >= 0);
        }
        if(c->i == c->data_len)
        {
            PyObject *data = PyObject_CallMethod(c->fd, "read", "i", c->buf_size - c->data_len);
            int n = PyString_Size(data);
            memcpy(c->data + c->data_len, PyString_AsString(data), n);
            c->data_len += n;
            Py_DECREF(data);
        }
        if(c->i == c->data_len)
        {
            if(c->last < c->i) {
                c->done = 1;
                return PyString_FromStringAndSize((char *)(c->data + c->last),
                                                  c->data_len - c->last);
            }
            PyErr_SetNone(PyExc_StopIteration);
            return NULL;
        }
        if(initial)
        {
            int bytes = MIN(initial, c->data_len - c->i);
            initial -= bytes;
            c->sum = checksum(c->data + c->i, bytes, 0);
            c->i += bytes;
        }
        else
        {
            c->sum = roll_checksum(c->sum,
                                   c->data[c->i - c->window_size],
                                   c->data[c->i],
                                   c->window_size);
            c->i++;
        }
        if((c->sum % c->chunk_size) == c->seed)
        {
            int old_last = c->last;
            c->last = c->i;
            return PyString_FromStringAndSize((char *)(c->data + old_last),
                                              c->last - old_last);
        }
        if(c->i == c->buf_size && c->last <= c->window_size)
        {
            int old_last = c->last;
            c->last = c->i;
            return PyString_FromStringAndSize((char *)(c->data + old_last),
                                              c->last - old_last);
        }
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
    PyObject *fd;
    int chunk_size, window_size, seed;
    ChunkifyIter *c;

    if (!PyArg_ParseTuple(args, "Oiii", &fd, &chunk_size, &window_size, &seed))
    {
        return NULL;
    }
    if (!(c = PyObject_New(ChunkifyIter, &ChunkifyIterType)))
    {
        return NULL;
    }
    PyObject_Init((PyObject *)c, &ChunkifyIterType);
    c->buf_size = 10 * 1024 * 1024;
    c->data = malloc(c->buf_size);
    c->fd = fd;
    c->chunk_size = chunk_size;
    c->window_size = window_size;
    c->seed = seed % chunk_size;
    Py_INCREF(fd);
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
