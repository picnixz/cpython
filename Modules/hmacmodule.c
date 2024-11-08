#ifndef Py_BUILD_CORE_BUILTIN
#  define Py_BUILD_CORE_MODULE 1
#endif

#include "Python.h"
#include "pycore_hashtable.h"
#include "pycore_strhex.h"      // _Py_strhex()

#include <openssl/obj_mac.h>    // LN_* macros

#include "_hacl/Hacl_HMAC.h"
#include "hashlib.h"

// HMAC underlying hash function static information.

/* MD-5 */
// (HACL_HID = md5)
#define Py_hmac_md5_block_size          64
#define Py_hmac_md5_digest_size         16
#define Py_hmac_md5_update_func         NULL
#define Py_hmac_md5_digest_func         Hacl_HMAC_compute_md5

/* SHA-1 family */
// HACL_HID = sha1
#define Py_hmac_sha1_block_size         64
#define Py_hmac_sha1_digest_size        20
#define Py_hmac_sha1_update_func        NULL
#define Py_hmac_sha1_digest_func        Hacl_HMAC_compute_sha1

/* SHA-2 family */
// HACL_HID = sha2_224
#define Py_hmac_sha2_224_block_size     64
#define Py_hmac_sha2_224_digest_size    28
#define Py_hmac_sha2_224_update_func    NULL
#define Py_hmac_sha2_224_digest_func    Hacl_HMAC_compute_sha2_224

// HACL_HID = sha2_256
#define Py_hmac_sha2_256_block_size     64
#define Py_hmac_sha2_256_digest_size    32
#define Py_hmac_sha2_256_update_func    NULL
#define Py_hmac_sha2_256_digest_func    Hacl_HMAC_compute_sha2_256

// HACL_HID = sha2_384
#define Py_hmac_sha2_384_block_size     128
#define Py_hmac_sha2_384_digest_size    48
#define Py_hmac_sha2_384_update_func    NULL
#define Py_hmac_sha2_384_digest_func    Hacl_HMAC_compute_sha2_384

// HACL_HID = sha2_512
#define Py_hmac_sha2_512_block_size     128
#define Py_hmac_sha2_512_digest_size    64
#define Py_hmac_sha2_512_update_func    NULL
#define Py_hmac_sha2_512_digest_func    Hacl_HMAC_compute_sha2_512

/* SHA-3 family */
// HACL_HID = sha3_224
#define Py_hmac_sha3_224_block_size     144
#define Py_hmac_sha3_224_digest_size    28
#define Py_hmac_sha3_224_update_func    NULL
#define Py_hmac_sha3_224_digest_func    Hacl_HMAC_compute_sha3_224

// HACL_HID = sha3_256
#define Py_hmac_sha3_256_block_size     136
#define Py_hmac_sha3_256_digest_size    32
#define Py_hmac_sha3_256_update_func    NULL
#define Py_hmac_sha3_256_digest_func    Hacl_HMAC_compute_sha3_256

// HACL_HID = sha3_384
#define Py_hmac_sha3_384_block_size     104
#define Py_hmac_sha3_384_digest_size    48
#define Py_hmac_sha3_384_update_func    NULL
#define Py_hmac_sha3_384_digest_func    Hacl_HMAC_compute_sha3_384

// HACL_HID = sha3_512
#define Py_hmac_sha3_512_block_size     72
#define Py_hmac_sha3_512_digest_size    64
#define Py_hmac_sha3_512_update_func    NULL
#define Py_hmac_sha3_512_digest_func    Hacl_HMAC_compute_sha3_512

/* Blake family */
// HACL_HID = blake2s_32
#define Py_hmac_blake2s_32_block_size   64
#define Py_hmac_blake2s_32_digest_size  32
#define Py_hmac_blake2s_32_update_func  NULL
#define Py_hmac_blake2s_32_digest_func  Hacl_HMAC_compute_blake2s_32

// HACL_HID = blake2b_32
#define Py_hmac_blake2b_32_block_size   128
#define Py_hmac_blake2b_32_digest_size  64
#define Py_hmac_blake2b_32_update_func  NULL
#define Py_hmac_blake2b_32_digest_func  Hacl_HMAC_compute_blake2b_32

#define Py_hmac_hash_max_digest_size    64

/* Enumeration indicating the underlying hash function used by HMAC. */
typedef enum HMAC_Hash_Kind {
    Py_HMAC_Hash_unknown = 0,
    /* MD5 */
    Py_HMAC_Hash_md5,
    /* SHA-1 */
    Py_HMAC_Hash_sha1,
    /* SHA-2 family */
    Py_HMAC_Hash_sha2_224,
    Py_HMAC_Hash_sha2_256,
    Py_HMAC_Hash_sha2_384,
    Py_HMAC_Hash_sha2_512,
    /* SHA-3 family */
    Py_HMAC_Hash_sha3_224,
    Py_HMAC_Hash_sha3_256,
    Py_HMAC_Hash_sha3_384,
    Py_HMAC_Hash_sha3_512,
    /* Blake family */
    Py_HMAC_Hash_blake2s_32,
    Py_HMAC_Hash_blake2b_32,
} HMAC_Hash_Kind;

typedef void (*HACL_HMAC_update_func)(void *state,
                                      uint8_t *buf, uint32_t buflen);

typedef void (*HACL_HMAC_digest_func)(uint8_t *out,
                                      uint8_t *key, uint32_t keylen,
                                      uint8_t *msg, uint32_t msglen);

/*
 * HMAC underlying hash function static information.
 *
 * The '_hmac' built-in module is able to recognize the same hash
 * functions as the '_hashlib' built-in module with the exception
 * of truncated SHA-2-512-224/256 which are not yet implemented by
 * the HACL* project.
 */
typedef struct py_hmac_hinfo {
    /*
     * Name of the hash function used by the HACL* HMAC module.
     *
     * This name may differ from the hashlib's names and OpenSSL names.
     * For instance, SHA-2/224 is named "sha2_224" instead of "sha224"
     * as it is done by 'hashlib'.
     */
    const char *name;
    /*
     * Optional field to cache storing the 'name' field as a Python string.
     *
     * This field is NULL by default in the items of "py_hmac_hinfo_table"
     * but will be populated when creating the module's state "hinfo_table".
     */
    PyObject *p_name;

    /* hash function information */
    HMAC_Hash_Kind kind;
    uint32_t block_size;
    uint32_t digest_size;

    /* hash function sub-routines */
    const HACL_HMAC_update_func update;
    const HACL_HMAC_digest_func digest;

    const char *hashlib_name;   /* hashlib preferred name (default: name) */
    const char *hashlib_altn;   /* hashlib alias (default: hashlib_name) */
    const char *openssl_name;   /* hashlib preferred OpenSSL alias (if any) */

    Py_ssize_t refcnt;
} py_hmac_hinfo;

/* Static information used to construct the hash table. */
static const py_hmac_hinfo py_hmac_static_hinfo[] = {
#define Py_HMAC_HID_ENTRY(HACL_HID, HLIB_NAME, HLIB_ALTN, OSSL_NAME)    \
{                                                                       \
    Py_STRINGIFY(HACL_HID), NULL,                                       \
    Py_HMAC_Hash_## HACL_HID,                                           \
    Py_hmac_## HACL_HID ##_block_size,                                  \
    Py_hmac_## HACL_HID ##_digest_size,                                 \
    Py_hmac_## HACL_HID ##_update_func,                                 \
    Py_hmac_## HACL_HID ##_digest_func,                                 \
    HLIB_NAME, HLIB_ALTN, OSSL_NAME,                                    \
    0,                                                                  \
}
    /* MD5 */
    Py_HMAC_HID_ENTRY(md5, "md5", "MD5", LN_md5),
    /* SHA-1 */
    Py_HMAC_HID_ENTRY(sha1, "sha1", "SHA1", LN_sha1),
    /* SHA-2 family */
    Py_HMAC_HID_ENTRY(sha2_224, "sha224", "SHA224", LN_sha224),
    Py_HMAC_HID_ENTRY(sha2_256, "sha256", "SHA256", LN_sha256),
    Py_HMAC_HID_ENTRY(sha2_384, "sha384", "SHA384", LN_sha384),
    Py_HMAC_HID_ENTRY(sha2_512, "sha512", "SHA512", LN_sha512),
    /* SHA-3 family */
    Py_HMAC_HID_ENTRY(sha3_224, NULL, NULL, LN_sha3_224),
    Py_HMAC_HID_ENTRY(sha3_256, NULL, NULL, LN_sha3_256),
    Py_HMAC_HID_ENTRY(sha3_384, NULL, NULL, LN_sha3_384),
    Py_HMAC_HID_ENTRY(sha3_512, NULL, NULL, LN_sha3_512),
    /* Blake family */
    Py_HMAC_HID_ENTRY(blake2s_32, "blake2s256", NULL, LN_blake2s256),
    Py_HMAC_HID_ENTRY(blake2b_32, "blake2b512", NULL, LN_blake2b512),
#undef Py_HMAC_HID_ENTRY
    /* sentinel */
    {NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, 0},
};

typedef struct hmacmodule_state {
    _Py_hashtable_t *hinfo_table;
    PyTypeObject *hmac_type;

    PyObject *str_lower;
} hmacmodule_state;

static inline hmacmodule_state *
get_hmacmodule_state(PyObject *module)
{
    void *state = PyModule_GetState(module);
    assert(state != NULL);
    return (hmacmodule_state *)state;
}

static inline hmacmodule_state *
get_hmacmodule_state_by_cls(PyTypeObject *cls)
{
    void *state = PyType_GetModuleState(cls);
    assert(state != NULL);
    return (hmacmodule_state *)state;
}

// --- HMAC module clinic configuration ---------------------------------------

typedef struct HMACObject HMACObject;

/*[clinic input]
module _hmac
class _hmac.HMAC "HMACObject *" "clinic_state()->hmac_type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=c8bab73fde49ba8a]*/

#define clinic_state()  (get_hmacmodule_state_by_cls(Py_TYPE(self)))
#include "clinic/hmacmodule.c.h"
#undef clinic_state

// --- HMAC Object ------------------------------------------------------------

typedef struct HMAC_State {
    uint8_t *key;       // user-specified key
    Py_ssize_t keylen;  // key length in bytes

    uint8_t *msg;       // aggregated message
    Py_ssize_t msglen;  // message length in bytes
} HMAC_State;

typedef struct HMACObject {
    PyObject_HEAD

    bool use_mutex;
    PyMutex mutex;

    // Hash function information
    PyObject *name;
    HMAC_Hash_Kind kind;
    uint32_t block_size;
    uint32_t digest_size;

    HACL_HMAC_update_func update;
    HACL_HMAC_digest_func digest;

    // HMAC internal state.
    HMAC_State *state;
} HMACObject;

#define _PyHMACObject_CAST(PTR)   ((HMACObject *)(PTR))

static int
find_hash_info_by_name(hmacmodule_state *state,
                       PyObject *name, const py_hmac_hinfo **info)
{
    assert(PyUnicode_Check(name));
    const char *utf8name = PyUnicode_AsUTF8(name);
    if (utf8name == NULL) {
        *info = NULL;
        return -1;
    }
    *info = _Py_hashtable_get(state->hinfo_table, utf8name);
    return *info != NULL;
}

static int
find_hash_info_by_func(hmacmodule_state *state,
                       PyObject *func, const py_hmac_hinfo **info)
{
    assert(PyCallable_Check(func));
    return 0;
}

static int
find_hash_info(hmacmodule_state *state,
               PyObject *str_or_fun, const py_hmac_hinfo **info)
{
    if (PyUnicode_Check(str_or_fun)) {
        int rc = find_hash_info_by_name(state, str_or_fun, info);
        if (rc == 0) {
            // try to find an alternative using the lowercase name
            PyObject *lowername = PyObject_CallMethodNoArgs(str_or_fun,
                                                            state->str_lower);
            if (lowername == NULL) {
                return -1;
            }
            rc = find_hash_info_by_name(state, lowername, info);
            Py_DECREF(lowername);
        }
        return rc;
    }
    if (PyCallable_Check(str_or_fun)) {
        return find_hash_info_by_func(state, str_or_fun, info);
    }
    return 0;
}

// --- HMAC object ------------------------------------------------------------

static int
hmac_set_hinfo(HMACObject *self, const py_hmac_hinfo *info)
{
    assert(info->p_name != NULL);
    self->name = Py_NewRef(info->p_name);
    self->kind = info->kind;
    self->block_size = info->block_size;
    self->digest_size = info->digest_size;

    self->update = info->update;
    self->digest = info->digest;
    return 0;
}

/*
 * Create a new internal state for the HMAC object.
 *
 * This must not be called before hmac_set_hinfo().
 */
static int
hmac_new_state(HMACObject *self,
               const uint8_t *key, Py_ssize_t keylen,
               const uint8_t *msg, Py_ssize_t msglen)
{
    self->state = PyMem_Malloc(sizeof(HMAC_State));
    if (self->state == NULL) {
        PyErr_NoMemory();
        return -1;
    }

    self->state->key = PyMem_New(uint8_t, keylen);
    if (self->state->key == NULL) {
        PyMem_Free(self->state);
        PyErr_NoMemory();
        return -1;
    }

    self->state->msg = PyMem_New(uint8_t, msglen);
    if (self->state->msg == NULL) {
        PyMem_Free(self->state->key);
        PyMem_Free(self->state);
        PyErr_NoMemory();
        return -1;
    }

    size_t keysize = sizeof(uint8_t) * keylen;  // guaranteed to fit
    memcpy(self->state->key, key, keysize);
    self->state->keylen = keylen;

    size_t msgsize = sizeof(uint8_t) * msglen;  // guaranteed to fit
    memcpy(self->state->msg, msg, msgsize);
    self->state->msglen = msglen;

    return 0;
}

/*[clinic input]
_hmac.new

    key as keyobj: object
    msg as msgobj: object(c_default="NULL") = b''
    digestmod: object(c_default="NULL") = None

Return a new HMAC object.
[clinic start generated code]*/

static PyObject *
_hmac_new_impl(PyObject *module, PyObject *keyobj, PyObject *msgobj,
               PyObject *digestmod)
/*[clinic end generated code: output=125488d5fe775e3a input=4fda486b338d881c]*/
{
    if (digestmod == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "Missing required parameter 'digestmod'.");
        return NULL;
    }

    hmacmodule_state *state = get_hmacmodule_state(module);

    const py_hmac_hinfo *info = NULL;
    int rc = find_hash_info(state, digestmod, &info);
    if (rc < 0) {
        return NULL;
    }
    if (rc == 0) {
        assert(info == NULL);
        // TODO: use a dedicated exception instead
        PyErr_Format(PyExc_ValueError, "unsupported hash type: %R", digestmod);
        return NULL;
    }

    HMACObject *self = PyObject_GC_New(HMACObject, state->hmac_type);
    if (self == NULL) {
        return NULL;
    }
    HASHLIB_INIT_MUTEX(self);
    if (hmac_set_hinfo(self, info) < 0) {
        goto error;
    }
    Py_buffer key, msg;
    GET_BUFFER_VIEW_OR_ERROR(keyobj, &key, goto error);
    GET_BUFFER_VIEW_OR_ERROR(msgobj, &msg, goto error);
    rc = hmac_new_state(self, key.buf, key.len, msg.buf, msg.len);
    PyBuffer_Release(&msg);
    PyBuffer_Release(&key);
    if (rc < 0) {
        goto error;
    }
    PyObject_GC_Track(self);
    return (PyObject *)self;
error:
    Py_DECREF(self);
    return NULL;
}

static int
hmac_copy_hinfo(HMACObject *out, const HMACObject *src)
{
    out->kind = src->kind;
    assert(src->name != NULL);
    out->name = Py_NewRef(src->name);
    out->block_size = src->block_size;
    out->digest_size = src->digest_size;
    return 0;
}

static inline int
hmac_copy_state(HMACObject *out, const HMACObject *src)
{
    const HMAC_State *st = src->state;
    return hmac_new_state(out, st->key, st->keylen, st->msg, st->msglen);
}

/*[clinic input]
_hmac.HMAC.copy

Return a copy ("clone") of the HMAC object.
[clinic start generated code]*/

static PyObject *
_hmac_HMAC_copy_impl(HMACObject *self)
/*[clinic end generated code: output=7f9ef0ac9e5ec264 input=b7889c62bd126c6a]*/
{
    hmacmodule_state *state = get_hmacmodule_state_by_cls(Py_TYPE(self));
    HMACObject *copy = PyObject_GC_New(HMACObject, state->hmac_type);
    if (copy == NULL) {
        return NULL;
    }
    HASHLIB_INIT_MUTEX(copy);

    ENTER_HASHLIB(self);
    /* copy hash information */
    if (hmac_copy_hinfo(copy, self) < 0) {
        goto error;
    }
    /* copy internal state */
    if (hmac_copy_state(copy, self) < 0) {
        goto error;
    }
    LEAVE_HASHLIB(self);

    PyObject_GC_Track(copy);
    return (PyObject *)copy;

error:
    LEAVE_HASHLIB(self);
    Py_DECREF(copy);
    return NULL;
}

/*[clinic input]
_hmac.HMAC.update

    msg as msgobj: object
    /

Update the HMAC object with the given message.
[clinic start generated code]*/

static PyObject *
_hmac_HMAC_update(HMACObject *self, PyObject *msgobj)
/*[clinic end generated code: output=16a8f95720732a18 input=8c1c988731ac66b9]*/
{
    Py_buffer msg;
    GET_BUFFER_VIEW_OR_ERROUT(msgobj, &msg);

    ENTER_HASHLIB(self);
    Py_ssize_t reslen = self->state->msglen + msg.len;
    if (PyMem_Resize(self->state->msg, uint8_t, reslen) == NULL) {
        LEAVE_HASHLIB(self);
        PyBuffer_Release(&msg);
        PyErr_NoMemory();
        return NULL;
    }
    memcpy(self->state->msg + self->state->msglen, msg.buf, msg.len);
    self->state->msglen = reslen;
    LEAVE_HASHLIB(self);

    PyBuffer_Release(&msg);
    return Py_NewRef(self);
}

static int
hmac_digest_compute(uint8_t *digest, HMACObject *self)
{
    uint8_t *key = self->state->key;
    Py_ssize_t keylen = self->state->keylen;

    uint8_t *msg = self->state->msg;
    Py_ssize_t msglen = self->state->keylen;
    // TODO: use HACL* update() functions for HMAC when available
    self->digest(digest, key, keylen, msg, msglen);
    return 0;
}

/*[clinic input]
_hmac.HMAC.digest

Return the digest of the bytes passed to the update() method so far.
[clinic start generated code]*/

static PyObject *
_hmac_HMAC_digest_impl(HMACObject *self)
/*[clinic end generated code: output=5bf3cc5862d26ada input=46ada2d337ddcc85]*/
{
    assert(self->digest_size <= Py_hmac_hash_max_digest_size);
    uint8_t digest[Py_hmac_hash_max_digest_size];
    ENTER_HASHLIB(self);
    int rc = hmac_digest_compute(digest, self);
    LEAVE_HASHLIB(self);
    if (rc < 0) {
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)digest, self->digest_size);
}

/*[clinic input]
_hmac.HMAC.hexdigest

Return hexadecimal digest of the bytes passed to the update() method so far.

This may be used to exchange the value safely in email or other non-binary
environments.
[clinic start generated code]*/

static PyObject *
_hmac_HMAC_hexdigest_impl(HMACObject *self)
/*[clinic end generated code: output=6659807a09ae14ec input=a7460247846b4c15]*/
{
    assert(self->digest_size <= Py_hmac_hash_max_digest_size);
    uint8_t digest[Py_hmac_hash_max_digest_size];
    ENTER_HASHLIB(self);
    int rc = hmac_digest_compute(digest, self);
    LEAVE_HASHLIB(self);
    if (rc < 0) {
        return NULL;
    }
    return _Py_strhex((const char *)digest, self->digest_size);
}

/*[clinic input]
@getter
_hmac.HMAC.name
[clinic start generated code]*/

static PyObject *
_hmac_HMAC_name_get_impl(HMACObject *self)
/*[clinic end generated code: output=ae693f09778d96d9 input=41c2c5dd1cf47fbc]*/
{
    return PyUnicode_FromFormat("hmac-%U", self->name);
}

/*[clinic input]
@getter
_hmac.HMAC.block_size
[clinic start generated code]*/

static PyObject *
_hmac_HMAC_block_size_get_impl(HMACObject *self)
/*[clinic end generated code: output=52cb11dee4e80cae input=9dda6b8d43e995b4]*/
{
    return PyLong_FromUInt32(self->block_size);
}

/*[clinic input]
@getter
_hmac.HMAC.digest_size
[clinic start generated code]*/

static PyObject *
_hmac_HMAC_digest_size_get_impl(HMACObject *self)
/*[clinic end generated code: output=22eeca1010ac6255 input=5622bb2840025b5a]*/
{
    return PyLong_FromUInt32(self->digest_size);
}

static PyObject *
HMACObject_repr(PyObject *self)
{
    HMACObject *hmac = _PyHMACObject_CAST(self);
    return PyUnicode_FromFormat("<%U HMAC object @ %p>", hmac->name, self);
}

static void
HMACObject_dealloc(PyObject *self)
{
    PyTypeObject *hmac_type = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    HMACObject *hmac = _PyHMACObject_CAST(self);
    Py_DECREF(hmac->name);
    PyMem_Free(hmac->state->msg);
    PyMem_Free(hmac->state->key);
    PyMem_Free(hmac->state);
    hmac_type->tp_free(self);
    Py_DECREF(hmac_type);
}

static int
HMACObject_traverse(PyObject *self, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(self));
    return 0;
}

static PyMethodDef HMACObject_methods[] = {
    _HMAC_HMAC_UPDATE_METHODDEF
    _HMAC_HMAC_DIGEST_METHODDEF
    _HMAC_HMAC_HEXDIGEST_METHODDEF
    _HMAC_HMAC_COPY_METHODDEF
    {NULL, NULL, 0, NULL}
};

static PyGetSetDef HMACObject_getsets[] = {
    _HMAC_HMAC_NAME_GETSETDEF
    _HMAC_HMAC_BLOCK_SIZE_GETSETDEF
    _HMAC_HMAC_DIGEST_SIZE_GETSETDEF
    {NULL, NULL, NULL, NULL, NULL} /* Sentinel */
};

static PyType_Slot HMACObject_Type_slots[] = {
    {Py_tp_repr, HMACObject_repr},
    {Py_tp_methods, HMACObject_methods},
    {Py_tp_getset, HMACObject_getsets},
    {Py_tp_dealloc, HMACObject_dealloc},
    {Py_tp_traverse, HMACObject_traverse},
    {0, NULL} /* Sentinel */
};

static PyType_Spec HMAC_Type_spec = {
    .name = "_hmac.HMAC",
    .basicsize = sizeof(HMACObject),
    .flags = Py_TPFLAGS_DEFAULT
             | Py_TPFLAGS_DISALLOW_INSTANTIATION
             | Py_TPFLAGS_IMMUTABLETYPE
             | Py_TPFLAGS_HAVE_GC,
    .slots = HMACObject_Type_slots,
};

/* Check that the buffer length fits on a uint32_t. */
static inline int
has_uint32_t_buffer_length(const Py_buffer *buffer)
{
#if PY_SSIZE_T_MAX > UINT32_MAX
    return buffer->len <= (Py_ssize_t)UINT32_MAX;
#else
    return 1;
#endif
}

/* One-shot HMAC-HASH using the given HACL_HID. */
#define Py_HMAC_HACL_ONESHOT(HACL_HID, KEY, MSG)                    \
    do {                                                            \
        Py_buffer keyview, msgview;                                 \
        GET_BUFFER_VIEW_OR_ERROUT((KEY), &keyview);                 \
        if (!has_uint32_t_buffer_length(&keyview)) {                \
            PyBuffer_Release(&keyview);                             \
            PyErr_SetString(PyExc_ValueError,                       \
                            "key length exceeds UINT32_MAX");       \
            return NULL;                                            \
        }                                                           \
        GET_BUFFER_VIEW_OR_ERROUT((MSG), &msgview);                 \
        if (!has_uint32_t_buffer_length(&msgview)) {                \
            PyBuffer_Release(&msgview);                             \
            PyBuffer_Release(&keyview);                             \
            PyErr_SetString(PyExc_ValueError,                       \
                            "message length exceeds UINT32_MAX");   \
            return NULL;                                            \
        }                                                           \
        uint8_t out[Py_hmac_## HACL_HID ##_digest_size];            \
        Py_hmac_## HACL_HID ##_digest_func(                         \
            out,                                                    \
            (uint8_t *)keyview.buf, (uint32_t)keyview.len,          \
            (uint8_t *)msgview.buf, (uint32_t)msgview.len           \
        );                                                          \
        PyBuffer_Release(&msgview);                                 \
        PyBuffer_Release(&keyview);                                 \
        return PyBytes_FromStringAndSize(                           \
            (const char *)out,                                      \
            Py_hmac_## HACL_HID ##_digest_size                      \
        );                                                          \
    } while (0)

/*[clinic input]
_hmac.compute_md5

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_md5_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=7837a4ceccbbf636 input=77a4b774c7d61218]*/
{
    Py_HMAC_HACL_ONESHOT(md5, key, msg);
}

/*[clinic input]
_hmac.compute_sha1

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha1_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=79fd7689c83691d8 input=3b64dccc6bdbe4ba]*/
{
    Py_HMAC_HACL_ONESHOT(sha1, key, msg);
}

/*[clinic input]
_hmac.compute_sha2_224

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha2_224_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=7f21f1613e53979e input=bcaac7a3637484ce]*/
{
    Py_HMAC_HACL_ONESHOT(sha2_224, key, msg);
}

/*[clinic input]
_hmac.compute_sha2_256

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha2_256_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=d4a291f7d9a82459 input=6e2d1f6fe9c56d21]*/
{
    Py_HMAC_HACL_ONESHOT(sha2_256, key, msg);
}

/*[clinic input]
_hmac.compute_sha2_384

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha2_384_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=f211fa26e3700c27 input=9ce8de89dda79e62]*/
{
    Py_HMAC_HACL_ONESHOT(sha2_384, key, msg);
}

/*[clinic input]
_hmac.compute_sha2_512

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha2_512_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=d5c20373762cecca input=b964bb8487d7debd]*/
{
    Py_HMAC_HACL_ONESHOT(sha2_512, key, msg);
}

/*[clinic input]
_hmac.compute_sha3_224

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha3_224_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=a242ccac9ad9c22b input=d0ab0c7d189c3d87]*/
{
    Py_HMAC_HACL_ONESHOT(sha3_224, key, msg);
}

/*[clinic input]
_hmac.compute_sha3_256

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha3_256_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=b539dbb61af2fe0b input=f05d7b6364b35d02]*/
{
    Py_HMAC_HACL_ONESHOT(sha3_256, key, msg);
}

/*[clinic input]
_hmac.compute_sha3_384

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha3_384_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=5eb372fb5c4ffd3a input=d842d393e7aa05ae]*/
{
    Py_HMAC_HACL_ONESHOT(sha3_384, key, msg);
}

/*[clinic input]
_hmac.compute_sha3_512

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_sha3_512_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=154bcbf8c2eacac1 input=166fe5baaeaabfde]*/
{
    Py_HMAC_HACL_ONESHOT(sha3_512, key, msg);
}

/*[clinic input]
_hmac.compute_blake2s_32

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_blake2s_32_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=cfc730791bc62361 input=d22c36e7fe31a985]*/
{
    Py_HMAC_HACL_ONESHOT(blake2s_32, key, msg);
}

/*[clinic input]
_hmac.compute_blake2b_32

    key: object
    msg: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_blake2b_32_impl(PyObject *module, PyObject *key, PyObject *msg)
/*[clinic end generated code: output=765c5c4fb9124636 input=4a35ee058d172f4b]*/
{
    Py_HMAC_HACL_ONESHOT(blake2b_32, key, msg);
}

static PyMethodDef hmacmodule_methods[] = {
    _HMAC_NEW_METHODDEF
    /* one-shot HMAC functions */
    _HMAC_COMPUTE_MD5_METHODDEF
    _HMAC_COMPUTE_SHA1_METHODDEF
    _HMAC_COMPUTE_SHA2_224_METHODDEF
    _HMAC_COMPUTE_SHA2_256_METHODDEF
    _HMAC_COMPUTE_SHA2_384_METHODDEF
    _HMAC_COMPUTE_SHA2_512_METHODDEF
    _HMAC_COMPUTE_SHA3_224_METHODDEF
    _HMAC_COMPUTE_SHA3_256_METHODDEF
    _HMAC_COMPUTE_SHA3_384_METHODDEF
    _HMAC_COMPUTE_SHA3_512_METHODDEF
    _HMAC_COMPUTE_BLAKE2S_32_METHODDEF
    _HMAC_COMPUTE_BLAKE2B_32_METHODDEF
    {NULL, NULL, 0, NULL}
};

// --- HMAC module initialization and finalization functions ------------------

static inline Py_uhash_t
py_hmac_hinfo_ht_hash(const void *name)
{
    return Py_HashBuffer(name, strlen((const char *)name));
}

static inline int
py_hmac_hinfo_ht_comp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b) == 0;
}

static inline void
py_hmac_hinfo_ht_free(void *hinfo)
{
    py_hmac_hinfo *entry = (py_hmac_hinfo *)hinfo;
    assert(entry->p_name != NULL);
    if (--(entry->refcnt) == 0) {
        Py_CLEAR(entry->p_name);
        PyMem_Free(hinfo);
    }
}

static inline int
py_hmac_hinfo_ht_add(_Py_hashtable_t *table, const void *key, void *info)
{
    if (key == NULL || _Py_hashtable_get(table, key) != NULL) {
        return 0;
    }
    int ok = _Py_hashtable_set(table, key, info);
    return ok < 0 ? -1 : ok == 0;
}

static _Py_hashtable_t *
py_hmac_hinfo_ht_new(void)
{
    _Py_hashtable_t *table = _Py_hashtable_new_full(
        py_hmac_hinfo_ht_hash,
        py_hmac_hinfo_ht_comp,
        NULL,
        py_hmac_hinfo_ht_free,
        NULL
    );

    if (table == NULL) {
        return NULL;
    }

    for (const py_hmac_hinfo *e = py_hmac_static_hinfo; e->name != NULL; e++) {
        py_hmac_hinfo *value = PyMem_Malloc(sizeof(py_hmac_hinfo));
        if (value == NULL) {
            goto error;
        }

        memcpy(value, e, sizeof(py_hmac_hinfo));
        assert(value->p_name == NULL);
        value->refcnt = 0;

#define Py_HMAC_HINFO_LINK(KEY)                                 \
        do {                                                    \
            int rc = py_hmac_hinfo_ht_add(table, KEY, value);   \
            if (rc < 0) {                                       \
                PyMem_Free(value);                              \
                goto error;                                     \
            }                                                   \
            else if (rc == 1) {                                 \
                value->refcnt++;                                \
            }                                                   \
        } while (0)
        Py_HMAC_HINFO_LINK(e->name);
        Py_HMAC_HINFO_LINK(e->hashlib_name);
        Py_HMAC_HINFO_LINK(e->hashlib_altn);
        Py_HMAC_HINFO_LINK(e->openssl_name);
#undef Py_HMAC_HINFO_LINK
        assert(value->refcnt > 0);
        value->p_name = PyUnicode_FromString(e->name);
        if (value->p_name == NULL) {
            PyMem_Free(value);
            goto error;
        }
    }

    return table;

error:
    _Py_hashtable_destroy(table);
    return NULL;
}

static int
hmacmodule_exec(PyObject *module)
{
    hmacmodule_state *state = get_hmacmodule_state(module);

    state->hinfo_table = py_hmac_hinfo_ht_new();
    if (state->hinfo_table == NULL) {
        // An exception other than a memory error can be raised
        // by PyUnicode_FromString() or _Py_hashtable_set() when
        // creating the hash table entries.
        if (!PyErr_Occurred()) {
            PyErr_NoMemory();
        }
        return -1;
    }

    state->hmac_type = (PyTypeObject *)PyType_FromModuleAndSpec(module,
                                                                &HMAC_Type_spec,
                                                                NULL);
    if (state->hmac_type == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, state->hmac_type) < 0) {
        return -1;
    }

    state->str_lower = PyUnicode_FromString("lower");
    if (state->str_lower == NULL) {
        return -1;
    }

    return 0;
}

static int
hmacmodule_traverse(PyObject *mod, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(mod));
    hmacmodule_state *state = get_hmacmodule_state(mod);
    Py_VISIT(state->hmac_type);
    Py_VISIT(state->str_lower);
    return 0;
}

static int
hmacmodule_clear(PyObject *mod)
{
    hmacmodule_state *state = get_hmacmodule_state(mod);
    if (state->hinfo_table != NULL) {
        _Py_hashtable_destroy(state->hinfo_table);
        state->hinfo_table = NULL;
    }
    Py_CLEAR(state->hmac_type);
    Py_CLEAR(state->str_lower);
    return 0;
}

static void
hmacmodule_free(void *mod)
{
    (void)hmacmodule_clear((PyObject *)mod);
}

static struct PyModuleDef_Slot hmacmodule_slots[] = {
    {Py_mod_exec, hmacmodule_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef _hmacmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_hmac",
    .m_size = sizeof(hmacmodule_state),
    .m_methods = hmacmodule_methods,
    .m_slots = hmacmodule_slots,
    .m_traverse = hmacmodule_traverse,
    .m_clear = hmacmodule_clear,
    .m_free = hmacmodule_free,
};

PyMODINIT_FUNC
PyInit__hmac(void)
{
    return PyModuleDef_Init(&_hmacmodule);
}
