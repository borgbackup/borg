#include "Python.h"

/*
 * This is not quite as dark magic as it looks. We just convert the address of (pointer to)
 * a PyObject into a bytes object in _wrap_object, and convert these bytes back to the
 * pointer to the original object.
 *
 * This mainly looks a bit confusing due to our mental special-casing of "char*" from other
 * pointers.
 *
 * The big upside to this is that this neither does *any* serialization (beyond creating tiny
 * bytes objects as "stand-ins"), nor has to copy the entire object that's passed around.
 */

static PyObject *
_object_to_optr(PyObject *obj)
{
    /*
     * Create a temporary reference to the object being passed around so it does not vanish.
     * Note that we never decref this one in _unwrap_object, since we just transfer that reference
     * there, i.e. there is an elided "Py_INCREF(x); Py_DECREF(x)".
     * Since the reference is transferred, calls to _wrap_object and _unwrap_object must be symmetric.
     */
    Py_INCREF(obj);
    return PyBytes_FromStringAndSize((const char*) &obj, sizeof(void*));
}

static PyObject *
_optr_to_object(PyObject *bytes)
{
    if(!PyBytes_Check(bytes)) {
        PyErr_SetString(PyExc_TypeError, "Cannot unwrap non-bytes object");
        return NULL;
    }
    if(PyBytes_Size(bytes) != sizeof(void*)) {
        PyErr_SetString(PyExc_TypeError, "Invalid length of bytes object");
        return NULL;
    }
    PyObject *object = * (PyObject **) PyBytes_AsString(bytes);
    return object;
}
