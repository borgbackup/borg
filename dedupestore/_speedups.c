#include <Python/Python.h>
#include <Python/structmember.h>

typedef struct {
  PyObject_HEAD
  long int m;
  long int i;
  long int chunk_size;
  unsigned long int sum;
  PyObject *data;
  PyObject *fd;
  PyObject *chunks;
} ChunkifyIter;

PyObject* ChunkifyIter_iter(PyObject *self)
{
  Py_INCREF(self);
  return self;
}

PyObject* ChunkifyIter_iternext(PyObject *self)
{
  ChunkifyIter *p = (ChunkifyIter *)self;
  if (p->i < p->m) {
    PyObject *tmp = Py_BuildValue("l", p->i);
    (p->i)++;
    return tmp;
  } else {
    /* Raising of standard StopIteration exception with empty value. */
    PyErr_SetNone(PyExc_StopIteration);
    return NULL;
  }
}

static PyTypeObject ChunkifyIterType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "_chunkifier._ChunkifyIter",       /*tp_name*/
    sizeof(ChunkifyIter),       /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    0,                         /*tp_dealloc*/
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
  PyObject *chunks;
  long int chunk_size;
  ChunkifyIter *p;

  if (!PyArg_ParseTuple(args, "OlO", &fd, &chunk_size, &chunks))  return NULL;

  /* I don't need python callable __init__() method for this iterator,
     so I'll simply allocate it as PyObject and initialize it by hand. */

  p = PyObject_New(ChunkifyIter, &ChunkifyIterType);
  if (!p) return NULL;

  /* I'm not sure if it's strictly necessary. */
  if (!PyObject_Init((PyObject *)p, &ChunkifyIterType)) {
    Py_DECREF(p);
    return NULL;
  }

    p->m = 10;
    p->i = 0;
    p->fd = fd;
    p->chunk_size = chunk_size;
    p->chunks = chunks;
    return (PyObject *)p;
  }

  static PyObject *
  checksum(PyObject *self, PyObject *args)
  {
    unsigned long int sum = 0, s1, s2;
    PyObject *data;
    Py_ssize_t i, len;
    const char *ptr;
    if (!PyArg_ParseTuple(args, "O|l", &data, &sum))  return NULL;
    len = PyString_Size(data);
    ptr = PyString_AsString(data);
    s1 = sum & 0xffff;
    s2 = sum >> 16;
    printf("Woot %lu\n", sizeof(s1));
    for(i=0; i < len; i++)
    {
        s1 += ptr[i] + 1;
        s2 += s1;
    }
    return PyInt_FromLong(((s2 & 0xffff) << 16) | (s1 & 0xffff));
}

static PyMethodDef ChunkifierMethods[] = {
    {"chunkify",  chunkify, METH_VARARGS, ""},
    {"checksum",  checksum, METH_VARARGS, ""},
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