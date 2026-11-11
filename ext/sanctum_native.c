#include <Python.h>

static PyObject* sanctum_stub_do_nothing(PyObject* self, PyObject* args) {
    /* Safe, non-destructive C stub. */
    Py_RETURN_NONE;
}

static PyMethodDef SanctumMethods[] = {
    {"do_nothing", sanctum_stub_do_nothing, METH_VARARGS, "Do nothing safely."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef sanctummodule = {
    PyModuleDef_HEAD_INIT,
    "sanctum_native",
    "SANCTUM Native Extension Stub",
    -1,
    SanctumMethods
};

PyMODINIT_FUNC PyInit_sanctum_native(void) {
    return PyModule_Create(&sanctummodule);
}
