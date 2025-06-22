/* SHA3 module
 *
 * This module provides an interface to the SHA3 algorithm
 *
 * See below for information about the original code this module was
 * based upon. Additional work performed by:
 *
 *  Andrew Kuchling (amk@amk.ca)
 *  Greg Stein (gstein@lyra.org)
 *  Trevor Perrin (trevp@trevp.net)
 *  Gregory P. Smith (greg@krypto.org)
 *  Bénédikt Tran (10796600+picnixz@users.noreply.github.com)
 *
 * Copyright (C) 2012-2022  Christian Heimes (christian@python.org)
 * Licensed to PSF under a Contributor Agreement.
 *
 */

#ifndef Py_BUILD_CORE_BUILTIN
#  define Py_BUILD_CORE_MODULE 1
#endif

#include "Python.h"
#include "pycore_strhex.h"        // _Py_strhex()
#include "pycore_typeobject.h"    // _PyType_GetModuleState()
#include "hashlib.h"

#include "_hacl/Hacl_Hash_SHA3.h"

/*
 * Assert that 'LEN' can be safely casted to uint32_t.
 *
 * The 'LEN' parameter should be convertible to Py_ssize_t.
 */
#if !defined(NDEBUG) && (PY_SSIZE_T_MAX > UINT32_MAX)
#define CHECK_HACL_UINT32_T_LENGTH(LEN) assert((LEN) < (Py_ssize_t)UINT32_MAX)
#else
#define CHECK_HACL_UINT32_T_LENGTH(LEN)
#endif

/*
 * Call a macro with all SHA-3 known digest sizes.
 *
 * The macro MACRO takes as input a SHA-3 digest size
 * and produces *syntactally correct* code.
 */
#define SHA3N_EXPAND_MACRO(MACRO)   \
    MACRO(224);                     \
    MACRO(256);                     \
    MACRO(384);                     \
    MACRO(512);

/*
 * Call a macro with all SHAKE known block sizes.
 *
 * The macro MACRO takes as input a SHAKE block size
 * and produces *syntactally correct* code.
 */
#define SHAKE_EXPAND_MACRO(MACRO)   \
    MACRO(128);                     \
    MACRO(256);

// SHA-3 and SHAKE are implemented similarly but their interface
// may differ. To distinguish the underlying interface, we use
// the following naming convention:
//
// * methods for SHA-3 or SHAKE     _sha3_agile_<NAME>[_getter]
// * methods for SHA-3              _sha3_agile_sha3_<NAME>[_getter]
// * methods for SHAKE              _sha3_agile_shake_<NAME>[_getter]
//
// * methods for SHA-3-N            _sha3_sha3_<N>_<NAME>[_getter]
// * methods for SHAKE-N            _sha3_shake<N>_<NAME>[_getter]
//
// Local helpers follow the same convention as above but do not
// start with an underscore in their names.
//
// Functions and variables associated with the type itself (slots, specs,
// docs, etc) are named after "SHA3_object_<NAME>" if they are independent
// of the object type or "<SHAKE|SHA3_><N>_<object|type>_<NAME>".

/* The state attribute name holding the corresponding (PyTypeObject *). */
#define SHA3N_T(N)                  sha3_ ## N ## _type
#define SHAKE_T(N)                  shake ## N ## _type

/* Name of a local (static) helper acting on Python objects. */
#define SHA3_HELPER(NAME)           sha3_agile_         ## NAME
#define SHA3_SHA3_HELPER(NAME)      sha3_agile_sha3_    ## NAME
#define SHA3_SHAKE_HELPER(NAME)     sha3_agile_shake_   ## NAME

/* Name of a SHA-3 object getter. */
#define SHA3N_SHA3_GETTER(N, NAME)  _sha3_sha3_ ## N ## _ ## NAME ## _getter
#define SHA3N_SHAKE_GETTER(N, NAME) _sha3_shake ## N ## _ ## NAME ## _getter

#define SHA3_GETTER(NAME)           _sha3_agile_        ## NAME ## _getter
#define SHA3_SHA3_GETTER(NAME)      _sha3_agile_sha3_   ## NAME ## _getter
#define SHA3_SHAKE_GETTER(NAME)     _sha3_agile_shake_  ## NAME ## _getter

/* The function implementing a SHA-3 type slot. */
#define SHA3_TYPE_SLOT(NAME)            SHA3object_     ## NAME
#define SHA3_SHA3_TYPE_SLOT(NAME)       SHA3N_object_   ## NAME
#define SHA3_SHAKE_TYPE_SLOT(NAME)      SHAKE_object_   ## NAME
/* The name of variables holding a SHA-3 type slot. */
#define SHA3N_SHA3_TYPE_SLOT(N, NAME)   SHA3_ ## N ## _object_ ## NAME
#define SHA3N_SHAKE_TYPE_SLOT(N, NAME)  SHAKE ## N ## _object_ ## NAME
/* The name of the array holding the different SHA-3 type slots. */
#define SHA3N_SHA3_TYPE_SLOT_ARRAY(N)   SHA3_ ## N ## _type_slots
#define SHA3N_SHAKE_TYPE_SLOT_ARRAY(N)  SHAKE ## N ## _type_slots
/* The name of the global variable holding the SHA-3 type spec. */
#define SHA3N_SHA3_TYPE_SPEC(N)         SHA3_ ## N ## _type_spec
#define SHA3N_SHAKE_TYPE_SPEC(N)        SHAKE ## N ## _type_spec

/* The SHA-3 message digest sizes, in bytes. */
#define SHA3_224_DIGEST_SIZE    28
#define SHA3_256_DIGEST_SIZE    32
#define SHA3_384_DIGEST_SIZE    48
#define SHA3_512_DIGEST_SIZE    64

#define SHA3_MAX_DIGEST_SIZE    64
#define SHA3N_DIGEST_SIZE(N)    SHA3_ ## N ## _ ## DIGEST_SIZE

// --- SHA-3 module state -----------------------------------------------------

typedef struct {
#define SHA3N_TYPE_DECL(N)  PyTypeObject *SHA3N_T(N);
    SHA3N_EXPAND_MACRO(SHA3N_TYPE_DECL)
#undef SHAKE_TYPE_DECL

#define SHAKE_TYPE_DECL(N)  PyTypeObject *SHAKE_T(N);
    SHAKE_EXPAND_MACRO(SHAKE_TYPE_DECL)
#undef SHA3N_TYPE_DECL
} sha3module_state;

static inline sha3module_state *
get_sha3module_state(PyObject *module)
{
    void *state = PyModule_GetState(module);
    assert(state != NULL);
    return (sha3module_state *)state;
}

// --- SHA-3 object -----------------------------------------------------------

typedef struct {
    HASHLIB_OBJECT_HEAD
    Hacl_Hash_SHA3_state_t *state;
} SHA3object;

#define SHA3object_CAST(op)     ((SHA3object *)(op))

// --- SHA-3 module clinic configuration --------------------------------------
//
// The underlying type object for the different classes is explicitly 'void *'
// as we do not need it for now. If this is needed, a `clinic_state()` macro
// should be created.

/*[clinic input]
module _sha3

class _sha3.sha3_224    "SHA3object *"  "void *"
class _sha3.sha3_256    "SHA3object *"  "void *"
class _sha3.sha3_384    "SHA3object *"  "void *"
class _sha3.sha3_512    "SHA3object *"  "void *"

class _sha3.shake128    "SHA3object *"  "void *"
class _sha3.shake256    "SHA3object *"  "void *"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=c4a65a163a43876c]*/

#include "clinic/sha3module.c.h"

static void
hacl_sha3_state_update(Hacl_Hash_SHA3_state_t *state,
                       uint8_t *buf, Py_ssize_t len)
{
    /*
     * Note: we explicitly ignore the error code on the basis that it would
     * take more than 1 billion years to overflow the maximum admissible length
     * for SHA-3 (2^64 - 1).
     */
#if PY_SSIZE_T_MAX > UINT32_MAX
    while (len > (Py_ssize_t)UINT32_MAX) {
        (void)Hacl_Hash_SHA3_update(state, buf, UINT32_MAX);
        len -= UINT32_MAX;
        buf += UINT32_MAX;
    }
#endif
    /* cast to uint32_t is now safe */
    (void)Hacl_Hash_SHA3_update(state, buf, (uint32_t)len);
}

static SHA3object *
SHA3_HELPER(gc_new)(PyTypeObject *type)
{
    SHA3object *self = PyObject_GC_New(SHA3object, type);
    if (self == NULL) {
        return NULL;
    }
    HASHLIB_INIT_MUTEX(self);
    PyObject_GC_Track(self);
    return self;
}

static PyObject *
SHA3_HELPER(new)(PyTypeObject *type,
                 PyObject *data, int usedforsecurity, PyObject *string,
                 Spec_Hash_Definitions_hash_alg algorithm)
{
    PyObject *msg = NULL;
    if (_Py_hashlib_data_argument(&msg, data, string) < 0) {
        return NULL;
    }

    Py_buffer buf = {NULL, NULL};
    if (msg) {
        GET_BUFFER_VIEW_OR_ERROUT(msg, &buf);
    }

    SHA3object *self = SHA3_HELPER(gc_new)(type);
    if (self == NULL) {
        goto error;
    }
    self->state = Hacl_Hash_SHA3_malloc(algorithm);
    if (self->state == NULL) {
        (void)PyErr_NoMemory();
        goto error;
    }

    if (msg) {
        if (buf.len >= HASHLIB_GIL_MINSIZE) {
            /* Do not use self->mutex here as this is the constructor
             * where it is not yet possible to have concurrent access. */
            Py_BEGIN_ALLOW_THREADS
                hacl_sha3_state_update(self->state, buf.buf, buf.len);
            Py_END_ALLOW_THREADS
        }
        else {
            hacl_sha3_state_update(self->state, buf.buf, buf.len);
        }
    }

    PyBuffer_Release(&buf);
    return (PyObject *)self;

error:
    Py_XDECREF(self);
    if (msg && buf.obj) {
        PyBuffer_Release(&buf);
    }
    return NULL;
}

#define SHA3N_OBJECT_NEW_IMPL_BODY(S, TYPE, DATA, USEDFORSECURITY, STRING)  \
    {                                                                       \
        return SHA3_HELPER(new)(TYPE, DATA, USEDFORSECURITY, STRING,        \
                                Spec_Hash_Definitions_ ## S);               \
    }

/*[clinic input]
@classmethod
_sha3.sha3_224.__new__ as SHA3_224_object_new

    data: object(c_default="NULL") = b''
    *
    usedforsecurity: bool = True
    string: object(c_default="NULL") = None

Return a new SHA-3-224 hash object.
[clinic start generated code]*/

static PyObject *
SHA3_224_object_new_impl(PyTypeObject *type, PyObject *data,
                         int usedforsecurity, PyObject *string)
/*[clinic end generated code: output=453146861e0bbe87 input=be111b1025d11e76]*/
SHA3N_OBJECT_NEW_IMPL_BODY(SHA3_224, type, data, usedforsecurity, string)

/*[clinic input]
@classmethod
_sha3.sha3_256.__new__ as SHA3_256_object_new = _sha3.sha3_224.__new__
Return a new SHA-3-256 hash object.
[clinic start generated code]*/

static PyObject *
SHA3_256_object_new_impl(PyTypeObject *type, PyObject *data,
                         int usedforsecurity, PyObject *string)
/*[clinic end generated code: output=6a739ccabbaa895c input=8e5ba0b0f72100bf]*/
SHA3N_OBJECT_NEW_IMPL_BODY(SHA3_256, type, data, usedforsecurity, string)

/*[clinic input]
@classmethod
_sha3.sha3_384.__new__ as SHA3_384_object_new = _sha3.sha3_224.__new__
Return a new SHA-3-384 hash object.
[clinic start generated code]*/

static PyObject *
SHA3_384_object_new_impl(PyTypeObject *type, PyObject *data,
                         int usedforsecurity, PyObject *string)
/*[clinic end generated code: output=61b3717e66f48a79 input=2f32d672d8a7f1fa]*/
SHA3N_OBJECT_NEW_IMPL_BODY(SHA3_384, type, data, usedforsecurity, string)

/*[clinic input]
@classmethod
_sha3.sha3_512.__new__ as SHA3_512_object_new = _sha3.sha3_224.__new__
Return a new SHA-3-512 hash object.
[clinic start generated code]*/

static PyObject *
SHA3_512_object_new_impl(PyTypeObject *type, PyObject *data,
                         int usedforsecurity, PyObject *string)
/*[clinic end generated code: output=8f7717c5eae41a16 input=0e8c3dc698b54421]*/
SHA3N_OBJECT_NEW_IMPL_BODY(SHA3_512, type, data, usedforsecurity, string)

/*[clinic input]
@classmethod
_sha3.shake128.__new__ as SHAKE128_object_new = _sha3.sha3_224.__new__
Return a new SHAKE-128 hash object.
[clinic start generated code]*/

static PyObject *
SHAKE128_object_new_impl(PyTypeObject *type, PyObject *data,
                         int usedforsecurity, PyObject *string)
/*[clinic end generated code: output=6dbd7b1df6e73e73 input=12dfc70bf291a2ed]*/
SHA3N_OBJECT_NEW_IMPL_BODY(Shake128, type, data, usedforsecurity, string)

/*[clinic input]
@classmethod
_sha3.shake256.__new__ as SHAKE256_object_new = _sha3.shake128.__new__
Return a new SHAKE-256 hash object.
[clinic start generated code]*/

static PyObject *
SHAKE256_object_new_impl(PyTypeObject *type, PyObject *data,
                         int usedforsecurity, PyObject *string)
/*[clinic end generated code: output=bed954e644635da0 input=c5285e663ab1c1d5]*/
SHA3N_OBJECT_NEW_IMPL_BODY(Shake256, type, data, usedforsecurity, string)
#undef SHA3N_OBJECT_NEW_IMPL_BODY

/* Internal methods for a hash object */

static int
SHA3_TYPE_SLOT(clear)(PyObject *op)
{
    SHA3object *self = SHA3object_CAST(op);
    if (self->state != NULL) {
        Hacl_Hash_SHA3_free(self->state);
        self->state = NULL;
    }
    return 0;
}

static void
SHA3_TYPE_SLOT(dealloc)(PyObject *self)
{
    PyTypeObject *tp = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    (void)SHA3object_clear(self);
    tp->tp_free(self);
    Py_DECREF(tp);
}

static int
SHA3_TYPE_SLOT(traverse)(PyObject *self, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(self));
    return 0;
}

/* External methods for a hash object */

/*[clinic input]
_sha3.sha3_224.copy as _sha3_agile_copy

Return a copy of the hash object.
[clinic start generated code]*/

static PyObject *
_sha3_agile_copy_impl(SHA3object *self)
/*[clinic end generated code: output=c6247c0f9c646612 input=26603628b6677295]*/
{
    SHA3object *copy = SHA3_HELPER(gc_new)(Py_TYPE(self));
    if (copy == NULL) {
        return NULL;
    }
    HASHLIB_ACQUIRE_LOCK(self);
    copy->state = Hacl_Hash_SHA3_copy(self->state);
    HASHLIB_RELEASE_LOCK(self);
    if (copy->state == NULL) {
        Py_DECREF(copy);
        return PyErr_NoMemory();
    }
    return (PyObject *)copy;
}

/*[clinic input]
_sha3.sha3_224.update as _sha3_agile_update

    data: object
    /

Update this hash object's state with the provided bytes-like object.
[clinic start generated code]*/

static PyObject *
_sha3_agile_update_impl(SHA3object *self, PyObject *data)
/*[clinic end generated code: output=7b2130fbe25c54db input=cfad7cd01a7bfd14]*/
{
    Py_buffer buf;
    GET_BUFFER_VIEW_OR_ERROUT(data, &buf);
    HASHLIB_EXTERNAL_INSTRUCTIONS_LOCKED(
        self, buf.len,
        hacl_sha3_state_update(self->state, buf.buf, buf.len)
    );
    PyBuffer_Release(&buf);
    Py_RETURN_NONE;
}

static uint32_t
SHA3_SHA3_HELPER(compute_digest_locked)(SHA3object *self, uint8_t *buf)
{
    assert(!Hacl_Hash_SHA3_is_shake(self->state));
    HASHLIB_ACQUIRE_LOCK(self);
    (void)Hacl_Hash_SHA3_digest(self->state, buf);
    HASHLIB_RELEASE_LOCK(self);
    return Hacl_Hash_SHA3_hash_len(self->state);
}

/*[clinic input]
_sha3.sha3_224.digest as _sha3_agile_sha3_digest

Return the digest value as a bytes object.
[clinic start generated code]*/

static PyObject *
_sha3_agile_sha3_digest_impl(SHA3object *self)
/*[clinic end generated code: output=17dea352d9229999 input=3eb6a9331ba803a6]*/
{
    assert(!Hacl_Hash_SHA3_is_shake(self->state));
    uint8_t digest[SHA3_MAX_DIGEST_SIZE];
    uint32_t digestlen = SHA3_SHA3_HELPER(compute_digest_locked)(self, digest);
    assert(digestlen <= SHA3_MAX_DIGEST_SIZE);
    return PyBytes_FromStringAndSize((const char *)digest, digestlen);
}

/*[clinic input]
_sha3.sha3_224.hexdigest as _sha3_agile_sha3_hexdigest

Return the digest value as a string of hexadecimal digits.
[clinic start generated code]*/

static PyObject *
_sha3_agile_sha3_hexdigest_impl(SHA3object *self)
/*[clinic end generated code: output=39d34160ce921cf6 input=dbec3b195ff5d2cd]*/
{
    assert(!Hacl_Hash_SHA3_is_shake(self->state));
    uint8_t digest[SHA3_MAX_DIGEST_SIZE];
    uint32_t digestlen = SHA3_SHA3_HELPER(compute_digest_locked)(self, digest);
    assert(digestlen <= SHA3_MAX_DIGEST_SIZE);
    return _Py_strhex((const char *)digest, digestlen);
}

static PyObject *
SHA3_GETTER(block_size)(PyObject *op, void *Py_UNUSED(closure))
{
    SHA3object *self = SHA3object_CAST(op);
    return PyLong_FromLong(Hacl_Hash_SHA3_block_len(self->state));
}

#define SHA3N_NAME_GETTER_DECL(N)                           \
    static inline PyObject *                                \
    SHA3N_SHA3_GETTER(N, name) (PyObject *Py_UNUSED(op),    \
                                void *Py_UNUSED(closure))   \
    {                                                       \
        assert(strlen("sha3_" # N) == 8);                   \
        return PyUnicode_FromStringAndSize("sha3_" # N, 8); \
    }
SHA3N_EXPAND_MACRO(SHA3N_NAME_GETTER_DECL)
#undef SHA3N_NAME_GETTER_DECL

static PyObject *
SHA3_SHA3_GETTER(digest_size)(PyObject *op, void *Py_UNUSED(closure))
{
    SHA3object *self = SHA3object_CAST(op);
    assert(!Hacl_Hash_SHA3_is_shake(self->state));
    return PyLong_FromLong(Hacl_Hash_SHA3_hash_len(self->state));
}

static PyObject *
SHA3_GETTER(_capacity_bits)(PyObject *op, void *Py_UNUSED(closure))
{
    SHA3object *self = SHA3object_CAST(op);
    uint32_t rate = Hacl_Hash_SHA3_block_len(self->state) * 8;
    assert(rate <= 1600);
    return PyLong_FromLong(1600 - rate);
}

static PyObject *
SHA3_GETTER(_rate_bits)(PyObject *op, void *Py_UNUSED(closure))
{
    SHA3object *self = SHA3object_CAST(op);
    uint32_t rate = Hacl_Hash_SHA3_block_len(self->state) * 8;
    return PyLong_FromLong(rate);
}

static PyObject *
SHA3_SHA3_GETTER(_suffix)(PyObject *op, void *Py_UNUSED(closure))
{
#ifndef NDEBUG
    SHA3object *self = SHA3object_CAST(op);
    assert(!Hacl_Hash_SHA3_is_shake(self->state));
#endif
    unsigned char suffix[2] = {0x06, 0};
    return PyBytes_FromStringAndSize((const char *)suffix, 1);
}

static PyMethodDef SHA3_SHA3_TYPE_SLOT(methods)[] = {
    _SHA3_AGILE_COPY_METHODDEF
    _SHA3_AGILE_UPDATE_METHODDEF
    _SHA3_AGILE_SHA3_DIGEST_METHODDEF
    _SHA3_AGILE_SHA3_HEXDIGEST_METHODDEF
    {NULL, NULL} /* sentinel */
};

#define SHA3N_TYPE_OBJECT_GETSETS_DEF_DECL(N)                               \
    static PyGetSetDef SHA3N_SHA3_TYPE_SLOT(N, getsets)[] = {               \
        {"name", SHA3N_SHA3_GETTER(N, name), NULL, NULL, NULL},             \
        {"block_size", SHA3_GETTER(block_size), NULL, NULL, NULL},          \
        {"digest_size", SHA3_SHA3_GETTER(digest_size), NULL, NULL, NULL},   \
        {"_capacity_bits", SHA3_GETTER(_capacity_bits), NULL, NULL, NULL},  \
        {"_rate_bits", SHA3_GETTER(_rate_bits), NULL, NULL, NULL},          \
        {"_suffix", SHA3_SHA3_GETTER(_suffix), NULL, NULL, NULL},           \
        {NULL} /* sentinel */                                               \
    };
SHA3N_EXPAND_MACRO(SHA3N_TYPE_OBJECT_GETSETS_DEF_DECL)
#undef SHA3N_TYPE_OBJECT_GETSETS_DEF_DECL

#define SHA3N_TYPE_OBJECT_SLOT_DOC(N)                                   \
    PyDoc_STR(                                                          \
        "sha3_" #N "([data], *, usedforsecurity=True) -> SHA3 object\n" \
        "\n"                                                            \
        "Return a new SHA3 hash object with a digest length of "        \
        Py_STRINGIFY(SHA3N_DIGEST_SIZE(N)) " bytes."                    \
    )
#define SHA3N_TYPE_OBJECT_SLOTS_DECL(N)                                 \
    static PyType_Slot SHA3N_SHA3_TYPE_SLOT_ARRAY(N)[] = {              \
        {Py_tp_clear, SHA3_TYPE_SLOT(clear)},                           \
        {Py_tp_dealloc, SHA3_TYPE_SLOT(dealloc)},                       \
        {Py_tp_traverse, SHA3_TYPE_SLOT(traverse)},                     \
        {Py_tp_doc, SHA3N_TYPE_OBJECT_SLOT_DOC(N)},                     \
        {Py_tp_methods, SHA3_SHA3_TYPE_SLOT(methods)},                  \
        {Py_tp_getset, SHA3N_SHA3_TYPE_SLOT(N, getsets)},               \
        {Py_tp_new, SHA3N_SHA3_TYPE_SLOT(N, new)},                      \
        {0, NULL}                                                       \
    };
SHA3N_EXPAND_MACRO(SHA3N_TYPE_OBJECT_SLOTS_DECL)
#undef SHA3N_TYPE_OBJECT_SLOTS_DECL
#undef SHA3N_TYPE_OBJECT_SLOT_DOC

// Using _PyType_GetModuleState() on these types is safe since they
// cannot be subclassed: they don't have the Py_TPFLAGS_BASETYPE flag.
#define SHA3N_TYPE_OBJECT_TYPE_SPEC_DECL(N)         \
    static PyType_Spec SHA3N_SHA3_TYPE_SPEC(N) = {  \
        .name = "_sha3.sha3_" # N,                  \
        .basicsize = sizeof(SHA3object),            \
        .flags = (                                  \
              Py_TPFLAGS_DEFAULT                    \
            | Py_TPFLAGS_IMMUTABLETYPE              \
            | Py_TPFLAGS_HAVE_GC                    \
        ),                                          \
        .slots = SHA3N_SHA3_TYPE_SLOT_ARRAY(N)      \
    };
SHA3N_EXPAND_MACRO(SHA3N_TYPE_OBJECT_TYPE_SPEC_DECL)
#undef SHA3N_TYPE_OBJECT_SLOTS_DECL

static int
sha3_shake_check_digest_length(Py_ssize_t length)
{
    if (length < 0) {
        PyErr_SetString(PyExc_ValueError, "negative digest length");
        return -1;
    }
    if ((size_t)length >= (1 << 29)) {
        /*
         * Raise OverflowError to match the semantics of OpenSSL SHAKE
         * when the digest length exceeds the range of a 'Py_ssize_t';
         * the exception message will however be different in this case.
         */
        PyErr_SetString(PyExc_OverflowError, "digest length is too large");
        return -1;
    }
    return 0;
}

/*[clinic input]
_sha3.shake128.digest as _sha3_agile_shake_digest

    length: uint32

Return the digest value as a bytes object.
[clinic start generated code]*/

static PyObject *
_sha3_agile_shake_digest_impl(SHA3object *self, uint32_t length)
/*[clinic end generated code: output=795e48b14dc14d6f input=99119839b7a66f75]*/
{
    if (sha3_shake_check_digest_length(length) < 0) {
        return NULL;
    }

    /*
     * Hacl_Hash_SHA3_squeeze() fails if the algorithm is not SHAKE,
     * or if the length is 0. In the latter case, we follow OpenSSL's
     * behavior and return an empty digest, without raising an error.
     */
    if (length == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_BYTES);
    }

    CHECK_HACL_UINT32_T_LENGTH(length);
    PyObject *digest = PyBytes_FromStringAndSize(NULL, length);
    uint8_t *buffer = (uint8_t *)PyBytes_AS_STRING(digest);
    HASHLIB_ACQUIRE_LOCK(self);
    (void)Hacl_Hash_SHA3_squeeze(self->state, buffer, (uint32_t)length);
    HASHLIB_RELEASE_LOCK(self);
    return digest;
}

/*[clinic input]
_sha3.shake128.hexdigest as _sha3_agile_shake_hexdigest

    length: uint32

Return the digest value as a string of hexadecimal digits.
[clinic start generated code]*/

static PyObject *
_sha3_agile_shake_hexdigest_impl(SHA3object *self, uint32_t length)
/*[clinic end generated code: output=1be85b774c2eec80 input=438e17f72e53d0a2]*/
{
    if (sha3_shake_check_digest_length(length) < 0) {
        return NULL;
    }

    /* See _sha3_shake_128_digest_impl() for the fast path rationale. */
    if (length == 0) {
        return Py_GetConstant(Py_CONSTANT_EMPTY_STR);
    }

    CHECK_HACL_UINT32_T_LENGTH(length);
    uint8_t *buffer = PyMem_Malloc(length);
    if (buffer == NULL) {
        return PyErr_NoMemory();
    }

    HASHLIB_ACQUIRE_LOCK(self);
    (void)Hacl_Hash_SHA3_squeeze(self->state, buffer, (uint32_t)length);
    HASHLIB_RELEASE_LOCK(self);
    PyObject *digest = _Py_strhex((const char *)buffer, length);
    PyMem_Free(buffer);
    return digest;
}

#define SHAKE_NAME_GETTER_DECL(N)                               \
    static inline PyObject *                                    \
    SHA3N_SHAKE_GETTER(N, name) (PyObject *Py_UNUSED(op),       \
                                 void *Py_UNUSED(closure))      \
    {                                                           \
        assert(strlen("shake_" # N) == 9);                      \
        return PyUnicode_FromStringAndSize("shake_" # N, 9);    \
    }
SHAKE_EXPAND_MACRO(SHAKE_NAME_GETTER_DECL)
#undef SHAKE_NAME_GETTER_DECL

static inline PyObject *
SHA3_SHAKE_GETTER(digest_size)(PyObject *op, void *Py_UNUSED(closure))
{
#ifndef NDEBUG
    SHA3object *self = SHA3object_CAST(op);
    assert(Hacl_Hash_SHA3_is_shake(self->state));
#endif
    // preserving legacy behavior: variable-length algorithms return 0
    return PyLong_FromLong(0);
}

static PyObject *
SHA3_SHAKE_GETTER(_suffix)(PyObject *Py_UNUSED(op), void *Py_UNUSED(closure))
{
    unsigned char suffix[2] = {0x1f, 0};
    return PyBytes_FromStringAndSize((const char *)suffix, 1);
}

static PyMethodDef SHA3_SHAKE_TYPE_SLOT(methods)[] = {
    _SHA3_AGILE_COPY_METHODDEF
    _SHA3_AGILE_UPDATE_METHODDEF
    _SHA3_AGILE_SHAKE_DIGEST_METHODDEF
    _SHA3_AGILE_SHAKE_HEXDIGEST_METHODDEF
    {NULL, NULL} /* sentinel */
};

#define SHAKE_TYPE_OBJECT_GETSETS_DEF_DECL(N)                               \
    static PyGetSetDef SHA3N_SHAKE_TYPE_SLOT(N, getsets)[] = {              \
        {"name", SHA3N_SHAKE_GETTER(N, name), NULL, NULL, NULL},            \
        {"block_size", SHA3_GETTER(block_size), NULL, NULL, NULL},          \
        {"digest_size", SHA3_SHAKE_GETTER(digest_size), NULL, NULL, NULL},  \
        {"_capacity_bits", SHA3_GETTER(_capacity_bits), NULL, NULL, NULL},  \
        {"_rate_bits", SHA3_GETTER(_rate_bits), NULL, NULL, NULL},          \
        {"_suffix", SHA3_SHAKE_GETTER(_suffix), NULL, NULL, NULL},          \
        {NULL} /* sentinel */                                               \
    };
SHAKE_EXPAND_MACRO(SHAKE_TYPE_OBJECT_GETSETS_DEF_DECL)
#undef SHAKE_TYPE_OBJECT_GETSETS_DEF_DECL

#define SHAKE_TYPE_OBJECT_SLOT_DOC(N)                                       \
    PyDoc_STR(                                                              \
        "shake_" #N "([data], *, usedforsecurity=True) -> SHAKE object\n"   \
        "\n"                                                                \
        "Return a new SHAKE hash object."                                   \
    )
#define SHAKE_TYPE_OBJECT_SLOTS_DECL(N)                                     \
    static PyType_Slot SHA3N_SHAKE_TYPE_SLOT_ARRAY(N)[] = {                 \
        {Py_tp_clear, SHA3_TYPE_SLOT(clear)},                               \
        {Py_tp_dealloc, SHA3_TYPE_SLOT(dealloc)},                           \
        {Py_tp_traverse, SHA3_TYPE_SLOT(traverse)},                         \
        {Py_tp_doc, SHAKE_TYPE_OBJECT_SLOT_DOC(N)},                         \
        {Py_tp_methods, SHA3_SHAKE_TYPE_SLOT(methods)},                     \
        {Py_tp_getset, SHA3N_SHAKE_TYPE_SLOT(N, getsets)},                  \
        {Py_tp_new, SHA3N_SHAKE_TYPE_SLOT(N, new)},                         \
        {0, NULL}                                                           \
    };
SHAKE_EXPAND_MACRO(SHAKE_TYPE_OBJECT_SLOTS_DECL)
#undef SHAKE_TYPE_OBJECT_SLOTS_DECL
#undef SHAKE_TYPE_OBJECT_SLOT_DOC

// Using _PyType_GetModuleState() on these types is safe since they
// cannot be subclassed: they don't have the Py_TPFLAGS_BASETYPE flag.
#define SHAKE_TYPE_OBJECT_TYPE_SPEC_DECL(N)         \
    static PyType_Spec SHA3N_SHAKE_TYPE_SPEC(N) = { \
        .name = "_sha3.shake_" # N,                 \
        .basicsize = sizeof(SHA3object),            \
        .flags = (                                  \
              Py_TPFLAGS_DEFAULT                    \
            | Py_TPFLAGS_IMMUTABLETYPE              \
            | Py_TPFLAGS_HAVE_GC                    \
        ),                                          \
        .slots = SHA3N_SHAKE_TYPE_SLOT_ARRAY(N)     \
    };
SHAKE_EXPAND_MACRO(SHAKE_TYPE_OBJECT_TYPE_SPEC_DECL)
#undef SHAKE_TYPE_OBJECT_TYPE_SPEC_DECL

static int
sha3module_traverse(PyObject *module, visitproc visit, void *arg)
{
    sha3module_state *state = get_sha3module_state(module);
    Py_VISIT(state->sha3_224_type);
    Py_VISIT(state->sha3_256_type);
    Py_VISIT(state->sha3_384_type);
    Py_VISIT(state->sha3_512_type);
    Py_VISIT(state->shake128_type);
    Py_VISIT(state->shake256_type);
    return 0;
}

static int
sha3module_clear(PyObject *module)
{
    sha3module_state *state = get_sha3module_state(module);
    Py_CLEAR(state->sha3_224_type);
    Py_CLEAR(state->sha3_256_type);
    Py_CLEAR(state->sha3_384_type);
    Py_CLEAR(state->sha3_512_type);
    Py_CLEAR(state->shake128_type);
    Py_CLEAR(state->shake256_type);
    return 0;
}

static void
sha3module_free(void *module)
{
    (void)sha3module_clear((PyObject *)module);
}

static int
sha3module_set_type(PyTypeObject **type, PyObject *module, PyType_Spec *spec)
{
    *type = (PyTypeObject *)PyType_FromModuleAndSpec(module, spec, NULL);
    if (*type == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, *type) < 0) {
        return -1;
    }
    return 0;
}

static int
sha3module_exec(PyObject *module)
{
    sha3module_state *state = get_sha3module_state(module);

#define SHA3_MAKE_TYPE(TYPE, TYPE_SPEC)                             \
    do {                                                            \
        if (sha3module_set_type(&TYPE, module, &TYPE_SPEC) < 0) {   \
            return -1;                                              \
        }                                                           \
    } while(0)

    SHA3_MAKE_TYPE(state->sha3_224_type, SHA3N_SHA3_TYPE_SPEC(224));
    SHA3_MAKE_TYPE(state->sha3_256_type, SHA3N_SHA3_TYPE_SPEC(256));
    SHA3_MAKE_TYPE(state->sha3_384_type, SHA3N_SHA3_TYPE_SPEC(384));
    SHA3_MAKE_TYPE(state->sha3_512_type, SHA3N_SHA3_TYPE_SPEC(512));

    SHA3_MAKE_TYPE(state->shake128_type, SHA3N_SHAKE_TYPE_SPEC(128));
    SHA3_MAKE_TYPE(state->shake256_type, SHA3N_SHAKE_TYPE_SPEC(256));
#undef SHA3_MAKE_TYPE

    if (PyModule_AddStringConstant(module, "implementation", "HACL") < 0) {
        return -1;
    }
    if (PyModule_AddIntConstant(module,
                                "_GIL_MINSIZE",
                                HASHLIB_GIL_MINSIZE) < 0) {
        return -1;
    }

    return 0;
}

static PyModuleDef_Slot sha3module_slots[] = {
    {Py_mod_exec, sha3module_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

/* Initialize this module. */
static struct PyModuleDef sha3module_def = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_sha3",
    .m_size = sizeof(sha3module_state),
    .m_slots = sha3module_slots,
    .m_traverse = sha3module_traverse,
    .m_clear = sha3module_clear,
    .m_free = sha3module_free,
};

PyMODINIT_FUNC
PyInit__sha3(void)
{
    return PyModuleDef_Init(&sha3module_def);
}
