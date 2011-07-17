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
    int chunk_size, window_size, last, done, buf_size, seed, remaining, position;
    PyObject *chunks, *fd;
    unsigned char *data;
} ChunkifyIter;

static PyObject*
ChunkifyIter_iter(PyObject *self)
{
    ChunkifyIter *c = (ChunkifyIter *)self;
    c->remaining = 0;
    c->position = 0;
    c->done = 0;
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

static void
ChunkifyIter_fill(PyObject *self)
{
    ChunkifyIter *c = (ChunkifyIter *)self;
    memmove(c->data, c->data + c->last, c->position + c->remaining - c->last);
    c->position -= c->last;
    c->last = 0;
    PyObject *data = PyObject_CallMethod(c->fd, "read", "i", c->buf_size - c->position - c->remaining);
    int n = PyString_Size(data);
    memcpy(c->data + c->position + c->remaining, PyString_AsString(data), n);
    c->remaining += n;
    Py_DECREF(data);
}

static PyObject*
ChunkifyIter_iternext(PyObject *self)
{
    ChunkifyIter *c = (ChunkifyIter *)self;
    unsigned long int sum;

    if(c->done) {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
    if(c->remaining <= c->window_size) {
        ChunkifyIter_fill(self);
    }
    if(c->remaining < c->window_size) {
        c->done = 1;
        if(c->remaining) {
            return PyBuffer_FromMemory(c->data + c->position, c->remaining);
        }
        else {
            PyErr_SetNone(PyExc_StopIteration);
            return NULL;
        }
    }
    sum = checksum(c->data + c->position, c->window_size, 0);
    c->remaining -= c->window_size;
    c->position += c->window_size;
    while(c->remaining && (sum & 0xffff) != c->seed) {
        sum = roll_checksum(sum, c->data[c->position - c->window_size],
                            c->data[c->position],
                            c->window_size);
        c->position++;
        c->remaining--;
        if(c->remaining == 0) {
            ChunkifyIter_fill(self);
        }
    }
    int old_last = c->last;
    c->last = c->position;
    return PyBuffer_FromMemory(c->data + old_last, c->last - old_last);
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


static PyMethodDef ChunkifierMethods[] = {
    {"chunkify",  chunkify, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
init_speedups(void)
{
  PyObject* m;

  ChunkifyIterType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&ChunkifyIterType) < 0)  return;

  m = Py_InitModule("_speedups", ChunkifierMethods);
}
