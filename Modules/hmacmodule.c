/*
 * Implement the HMAC algorithm as described by RFC 2104 using HACL*.
 */

#ifndef Py_BUILD_CORE_BUILTIN
#  define Py_BUILD_CORE_MODULE 1
#endif

#include "Python.h"
#include "pycore_hashtable.h"
#include "pycore_strhex.h"              // _Py_strhex()

#include <openssl/evp.h>                // EVP_* interface
#include <openssl/objects.h>            // LN_* and NID_* macros

#include "_hacl/Hacl_HMAC.h"
#include "_hacl/Hacl_Streaming_Types.h" // Hacl_Streaming_Types_error_code

#include "hashlib.h"

// --- OpenSSL EVP interface (used for resolving algorithm names) -------------

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  define Py_EVP_MD                             EVP_MD
#  define Py_EVP_MD_fetch(ALGO)                 EVP_MD_fetch(NULL, ALGO, NULL)
#  define Py_EVP_MD_free(MD)                    EVP_MD_free(MD)
#else
#  define Py_EVP_MD                             const EVP_MD
#  define Py_EVP_MD_fetch(ALGO)                 EVP_get_digestbyname(ALGO)
#  define Py_EVP_MD_free(MD)                    do {} while(0)
#endif

// --- HMAC underlying hash function static information -----------------------

#define Py_hmac_hash_max_digest_size            64

#define Py_OpenSSL_LN_MISSING                   NULL
#define Py_OpenSSL_NID_MISSING                  -1

#define Py_hmac_hash_max_digest_size            64

/* MD-5 */
// HACL_HID = md5
#define Py_hmac_md5_block_size                  64
#define Py_hmac_md5_digest_size                 16

#define Py_hmac_md5_state_free_func             NULL
#define Py_hmac_md5_state_malloc_func           NULL
#define Py_hmac_md5_state_copy_func             NULL

#define Py_hmac_md5_update_func                 NULL
#define Py_hmac_md5_digest_func                 NULL
#define Py_hmac_md5_compute_func                Hacl_HMAC_compute_md5

#define Py_OpenSSL_LN_md5                       LN_md5
#define Py_OpenSSL_NID_md5                      NID_md5

/* SHA-1 family */
// HACL_HID = sha1
#define Py_hmac_sha1_block_size                 64
#define Py_hmac_sha1_digest_size                20

#define Py_hmac_sha1_state_free_func            NULL
#define Py_hmac_sha1_state_malloc_func          NULL
#define Py_hmac_sha1_state_copy_func            NULL

#define Py_hmac_sha1_update_func                NULL
#define Py_hmac_sha1_digest_func                NULL
#define Py_hmac_sha1_compute_func               Hacl_HMAC_compute_sha1

#define Py_OpenSSL_LN_sha1                      LN_sha1
#define Py_OpenSSL_NID_sha1                     NID_sha1

/* SHA-2 family */
// HACL_HID = sha2_224
#define Py_hmac_sha2_224_block_size             64
#define Py_hmac_sha2_224_digest_size            28

#define Py_hmac_sha2_224_state_free_func        NULL
#define Py_hmac_sha2_224_state_malloc_func      NULL
#define Py_hmac_sha2_224_state_copy_func        NULL

#define Py_hmac_sha2_224_update_func            NULL
#define Py_hmac_sha2_224_digest_func            NULL
#define Py_hmac_sha2_224_compute_func           Hacl_HMAC_compute_sha2_224

#define Py_OpenSSL_LN_sha2_224                  LN_sha224
#define Py_OpenSSL_NID_sha2_224                 NID_sha224

// HACL_HID = sha2_256
#define Py_hmac_sha2_256_block_size             64
#define Py_hmac_sha2_256_digest_size            32

#define Py_hmac_sha2_256_state_free_func        NULL
#define Py_hmac_sha2_256_state_malloc_func      NULL
#define Py_hmac_sha2_256_state_copy_func        NULL

#define Py_hmac_sha2_256_update_func            NULL
#define Py_hmac_sha2_256_digest_func            NULL
#define Py_hmac_sha2_256_compute_func           Hacl_HMAC_compute_sha2_256

#define Py_OpenSSL_LN_sha2_256                  LN_sha256
#define Py_OpenSSL_NID_sha2_256                 NID_sha256

// HACL_HID = sha2_384
#define Py_hmac_sha2_384_block_size             128
#define Py_hmac_sha2_384_digest_size            48

#define Py_hmac_sha2_384_state_free_func        NULL
#define Py_hmac_sha2_384_state_malloc_func      NULL
#define Py_hmac_sha2_384_state_copy_func        NULL

#define Py_hmac_sha2_384_update_func            NULL
#define Py_hmac_sha2_384_digest_func            NULL
#define Py_hmac_sha2_384_compute_func           Hacl_HMAC_compute_sha2_384

#define Py_OpenSSL_LN_sha2_384                  LN_sha384
#define Py_OpenSSL_NID_sha2_384                 NID_sha384

// HACL_HID = sha2_512
#define Py_hmac_sha2_512_block_size             128
#define Py_hmac_sha2_512_digest_size            64

#define Py_hmac_sha2_512_state_free_func        NULL
#define Py_hmac_sha2_512_state_malloc_func      NULL
#define Py_hmac_sha2_512_state_copy_func        NULL

#define Py_hmac_sha2_512_update_func            NULL
#define Py_hmac_sha2_512_digest_func            NULL
#define Py_hmac_sha2_512_compute_func           Hacl_HMAC_compute_sha2_512

#define Py_OpenSSL_LN_sha2_512                  LN_sha512
#define Py_OpenSSL_NID_sha2_512                 NID_sha512

/* SHA-3 family */
// HACL_HID = sha3_224
#define Py_hmac_sha3_224_block_size             144
#define Py_hmac_sha3_224_digest_size            28

#define Py_hmac_sha3_224_state_free_func        NULL
#define Py_hmac_sha3_224_state_malloc_func      NULL
#define Py_hmac_sha3_224_state_copy_func        NULL

#define Py_hmac_sha3_224_update_func            NULL
#define Py_hmac_sha3_224_digest_func            NULL
#define Py_hmac_sha3_224_compute_func           Hacl_HMAC_compute_sha3_224

#if defined(LN_sha3_224) && defined(NID_sha3_224)
#  define Py_OpenSSL_LN_sha3_224                LN_sha3_224
#  define Py_OpenSSL_NID_sha3_224               NID_sha3_224
#else
#  define Py_OpenSSL_LN_sha3_224                Py_OpenSSL_LN_MISSING
#  define Py_OpenSSL_NID_sha3_224               Py_OpenSSL_NID_MISSING
#endif

// HACL_HID = sha3_256
#define Py_hmac_sha3_256_block_size             136
#define Py_hmac_sha3_256_digest_size            32

#define Py_hmac_sha3_256_state_free_func        NULL
#define Py_hmac_sha3_256_state_malloc_func      NULL
#define Py_hmac_sha3_256_state_copy_func        NULL

#define Py_hmac_sha3_256_update_func            NULL
#define Py_hmac_sha3_256_digest_func            NULL
#define Py_hmac_sha3_256_compute_func           Hacl_HMAC_compute_sha3_256

#if defined(LN_sha3_256) && defined(NID_sha3_256)
#  define Py_OpenSSL_LN_sha3_256                LN_sha3_256
#  define Py_OpenSSL_NID_sha3_256               NID_sha3_256
#else
#  define Py_OpenSSL_LN_sha3_256                Py_OpenSSL_LN_MISSING
#  define Py_OpenSSL_NID_sha3_256               Py_OpenSSL_NID_MISSING
#endif

// HACL_HID = sha3_384
#define Py_hmac_sha3_384_block_size             104
#define Py_hmac_sha3_384_digest_size            48

#define Py_hmac_sha3_384_state_free_func        NULL
#define Py_hmac_sha3_384_state_malloc_func      NULL
#define Py_hmac_sha3_384_state_copy_func        NULL

#define Py_hmac_sha3_384_update_func            NULL
#define Py_hmac_sha3_384_digest_func            NULL
#define Py_hmac_sha3_384_compute_func           Hacl_HMAC_compute_sha3_384

#if defined(LN_sha3_384) && defined(NID_sha3_384)
#  define Py_OpenSSL_LN_sha3_384                LN_sha3_384
#  define Py_OpenSSL_NID_sha3_384               NID_sha3_384
#else
#  define Py_OpenSSL_LN_sha3_384                Py_OpenSSL_LN_MISSING
#  define Py_OpenSSL_NID_sha3_384               Py_OpenSSL_NID_MISSING
#endif

// HACL_HID = sha3_512
#define Py_hmac_sha3_512_block_size             72
#define Py_hmac_sha3_512_digest_size            64

#define Py_hmac_sha3_512_state_free_func        NULL
#define Py_hmac_sha3_512_state_malloc_func      NULL
#define Py_hmac_sha3_512_state_copy_func        NULL

#define Py_hmac_sha3_512_update_func            NULL
#define Py_hmac_sha3_512_digest_func            NULL
#define Py_hmac_sha3_512_compute_func           Hacl_HMAC_compute_sha3_512

#if defined(LN_sha3_512) && defined(NID_sha3_512)
#  define Py_OpenSSL_LN_sha3_512                LN_sha3_512
#  define Py_OpenSSL_NID_sha3_512               NID_sha3_512
#else
#  define Py_OpenSSL_LN_sha3_512                Py_OpenSSL_LN_MISSING
#  define Py_OpenSSL_NID_sha3_512               Py_OpenSSL_NID_MISSING
#endif

/* Blake2 family */
// HACL_HID = blake2s_32
#define Py_hmac_blake2s_32_block_size           64
#define Py_hmac_blake2s_32_digest_size          32

#define Py_hmac_blake2s_32_state_free_func      NULL
#define Py_hmac_blake2s_32_state_malloc_func    NULL
#define Py_hmac_blake2s_32_state_copy_func      NULL

#define Py_hmac_blake2s_32_update_func          NULL
#define Py_hmac_blake2s_32_digest_func          NULL
#define Py_hmac_blake2s_32_compute_func         Hacl_HMAC_compute_blake2s_32
#if defined(LN_blake2s256) && defined(NID_blake2s256)

#  define Py_OpenSSL_LN_blake2s_32              LN_blake2s256
#  define Py_OpenSSL_NID_blake2s_32             NID_blake2s256
#else
#  define Py_OpenSSL_LN_blake2s_32              Py_OpenSSL_LN_MISSING
#  define Py_OpenSSL_NID_blake2s_32             Py_OpenSSL_NID_MISSING
#endif

// HACL_HID = blake2b_32
#define Py_hmac_blake2b_32_block_size           128
#define Py_hmac_blake2b_32_digest_size          64

#define Py_hmac_blake2b_32_state_free_func      NULL
#define Py_hmac_blake2b_32_state_malloc_func    NULL
#define Py_hmac_blake2b_32_state_copy_func      NULL

#define Py_hmac_blake2b_32_update_func          NULL
#define Py_hmac_blake2b_32_digest_func          NULL
#define Py_hmac_blake2b_32_compute_func         Hacl_HMAC_compute_blake2b_32

#if defined(LN_blake2b512) && defined(NID_blake2b512)
#  define Py_OpenSSL_LN_blake2b_32              LN_blake2b512
#  define Py_OpenSSL_NID_blake2b_32             NID_blake2b512
#else
#  define Py_OpenSSL_LN_blake2b_32              Py_OpenSSL_LN_MISSING
#  define Py_OpenSSL_NID_blake2b_32             Py_OpenSSL_NID_MISSING
#endif

/* Enumeration indicating the underlying hash function used by HMAC. */
typedef enum HMAC_Hash_Kind {
    Py_hmac_kind_unknown = 0,
    /* MD5 */
    Py_hmac_kind_hmac_md5,
    /* SHA-1 */
    Py_hmac_kind_hmac_sha1,
    /* SHA-2 family */
    Py_hmac_kind_hmac_sha2_224,
    Py_hmac_kind_hmac_sha2_256,
    Py_hmac_kind_hmac_sha2_384,
    Py_hmac_kind_hmac_sha2_512,
    /* SHA-3 family */
    Py_hmac_kind_hmac_sha3_224,
    Py_hmac_kind_hmac_sha3_256,
    Py_hmac_kind_hmac_sha3_384,
    Py_hmac_kind_hmac_sha3_512,
    /* Blake family */
    Py_hmac_kind_hmac_blake2s_32,
    Py_hmac_kind_hmac_blake2b_32,
} HMAC_Hash_Kind;

/* Function pointer type for HACL* streaming HMAC state allocation */
typedef void *(*HACL_HMAC_state_malloc_func)(void);
/* Function pointer type for HACL* streaming HMAC state deallocation */
typedef void (*HACL_HMAC_state_free_func)(void *state);
/* Function pointer type for HACL* streaming HMAC state copy */
typedef void *(*HACL_HMAC_state_copy_func)(void *state);

/* Function pointer type for HACL* streaming HMAC update functions. */
typedef Hacl_Streaming_Types_error_code
(*HACL_HMAC_update_func)(void *state, uint8_t *buf, uint32_t len);

/* Function pointer type for HACL* streaming HMAC digest functions. */
typedef Hacl_Streaming_Types_error_code
(*HACL_HMAC_digest_func)(void *state, uint8_t *out);

/* Function pointer type for 1-shot HACL* HMAC functions. */
typedef void
(*HACL_HMAC_compute_func)(uint8_t *out,
                          uint8_t *key, uint32_t keylen,
                          uint8_t *msg, uint32_t msglen);

/* Function pointer type for 1-shot HACL* HMAC CPython AC functions. */
typedef PyObject *
(*PYAC_HMAC_compute_func)(PyObject *module, PyObject *key, PyObject *msg);

#if PY_SSIZE_T_MAX > UINT32_MAX
#define Py_HMAC_HACL_UPDATE_LOOP(UPDATE_FUNC, HACL_STATE, BUF, LEN) \
    do {                                                            \
        while (LEN > UINT32_MAX) {                                  \
            UPDATE_FUNC(HACL_STATE, BUF, UINT32_MAX);               \
            LEN -= UINT32_MAX;                                      \
            BUF += UINT32_MAX;                                      \
        }                                                           \
    } while (0)
#else
#define Py_HMAC_HACL_UPDATE_LOOP(UPDATE_FUNC, HACL_STATE, BUF, LEN)
#endif

/*
 * HACL* HMAC minimal interface.
 */
typedef struct py_hmac_hacl_api {
    HACL_HMAC_state_malloc_func malloc;
    HACL_HMAC_state_free_func free;
    HACL_HMAC_state_copy_func copy;

    HACL_HMAC_update_func update;
    HACL_HMAC_digest_func digest;

    HACL_HMAC_compute_func compute;
    PYAC_HMAC_compute_func compute_py;
} py_hmac_hacl_api;

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
     * This name may differ from the hashlib names and OpenSSL names.
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

    /* HACL* HMAC API */
    py_hmac_hacl_api api;

    const char *hashlib_name;   /* hashlib preferred name (default: name) */
    const char *openssl_name;   /* OpenSSL EVP preferred name (NULL if none) */
    int openssl_nid;            /* OpenSSL EVP NID (-1 if none) */

    Py_ssize_t refcnt;
} py_hmac_hinfo;

// --- HMAC module state ------------------------------------------------------

typedef struct hmacmodule_state {
    _Py_hashtable_t *hinfo_table;
    /* imported from _hashlib */
    PyObject *hashlib_constructs_mappingproxy;
    PyObject *hashlib_unsupported_digestmod_error;
    /* HMAC object type */
    PyTypeObject *hmac_type;
    /* interned strings */
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
    PyObject *name;         // rendered name
    HMAC_Hash_Kind kind;    // can be used for runtime dispatch
    uint32_t block_size;
    uint32_t digest_size;
    py_hmac_hacl_api api;

    // HMAC HACL* internal state.
    HMAC_State *state;
} HMACObject;

#define _PyHMACObject_CAST(PTR)   ((HMACObject *)(PTR))

// --- Helpers ----------------------------------------------------------------


/* Static information used to construct the hash table. */
static const py_hmac_hinfo py_hmac_static_hinfo[] = {
#define Py_HMAC_HINFO_HACL_API(HACL_HID)                                \
    {                                                                   \
        .malloc = Py_hmac_## HACL_HID ##_state_malloc_func,             \
        .free = Py_hmac_## HACL_HID ##_state_free_func,                 \
        .copy = Py_hmac_## HACL_HID ##_state_copy_func,                 \
        .update = Py_hmac_## HACL_HID ##_update_func,                   \
        .digest = Py_hmac_## HACL_HID ##_digest_func,                   \
        .compute = &Py_hmac_## HACL_HID ##_compute_func,                \
        .compute_py = &_hmac_compute_## HACL_HID ##_impl,               \
    }

#define Py_HMAC_HINFO_ENTRY(HACL_HID, HLIB_NAME)            \
    {                                                       \
        .name = Py_STRINGIFY(HACL_HID),                     \
        .p_name = NULL,                                     \
        .kind = Py_hmac_kind_hmac_ ## HACL_HID,             \
        .block_size = Py_hmac_## HACL_HID ##_block_size,    \
        .digest_size = Py_hmac_## HACL_HID ##_digest_size,  \
        .api = Py_HMAC_HINFO_HACL_API(HACL_HID),            \
        .hashlib_name = HLIB_NAME,                          \
        .openssl_name = Py_OpenSSL_LN_ ## HACL_HID,         \
        .openssl_nid =  Py_OpenSSL_NID_ ## HACL_HID,        \
        .refcnt = 0,                                        \
    }
    /* MD5 */
    Py_HMAC_HINFO_ENTRY(md5, "md5"),
    /* SHA-1 */
    Py_HMAC_HINFO_ENTRY(sha1, "sha1"),
    /* SHA-2 family */
    Py_HMAC_HINFO_ENTRY(sha2_224, "sha224"),
    Py_HMAC_HINFO_ENTRY(sha2_256, "sha256"),
    Py_HMAC_HINFO_ENTRY(sha2_384, "sha384"),
    Py_HMAC_HINFO_ENTRY(sha2_512, "sha512"),
    /* SHA-3 family */
    Py_HMAC_HINFO_ENTRY(sha3_224, NULL),
    Py_HMAC_HINFO_ENTRY(sha3_256, NULL),
    Py_HMAC_HINFO_ENTRY(sha3_384, NULL),
    Py_HMAC_HINFO_ENTRY(sha3_512, NULL),
    /* Blake family */
    Py_HMAC_HINFO_ENTRY(blake2s_32, "blake2s256"),
    Py_HMAC_HINFO_ENTRY(blake2b_32, "blake2b512"),
#undef Py_HMAC_HINFO_ENTRY
#undef Py_HMAC_HINFO_HACL_API
    /* sentinel */
    {
        NULL, NULL, Py_hmac_kind_unknown, 0, 0,
        {NULL, NULL},
        NULL, Py_OpenSSL_LN_MISSING, Py_OpenSSL_NID_MISSING,
        0,
    },
};

static inline bool
find_hash_info_by_utf8name(hmacmodule_state *state,
                           const char *name,
                           const py_hmac_hinfo **info)
{
    assert(name != NULL);
    *info = _Py_hashtable_get(state->hinfo_table, name);
    return *info != NULL;
}

static bool
find_hash_info_by_evp_nid(hmacmodule_state *state,
                          int openssl_nid,
                          const py_hmac_hinfo **info)
{
    assert(openssl_nid != Py_OpenSSL_NID_MISSING);
    for (const py_hmac_hinfo *e = py_hmac_static_hinfo; e->name != NULL; e++) {
        if (e->openssl_nid == openssl_nid) {
            assert(e->openssl_name != Py_OpenSSL_LN_MISSING);
            *info = e;
            return 1;
        }
    }
    *info = NULL;
    return 0;
}

static bool
find_hash_info_by_evp_name(hmacmodule_state *state,
                           const char *openssl_name,
                           const py_hmac_hinfo **info)
{
    assert(openssl_name != NULL);
    Py_EVP_MD *digest = Py_EVP_MD_fetch(openssl_name);
    if (digest == NULL) {
        *info = NULL;
        return 0;
    }
    int nid = EVP_MD_nid(digest);
    Py_EVP_MD_free(digest);
    return find_hash_info_by_evp_nid(state, nid, info);
}

static int
find_hash_info_by_name(hmacmodule_state *state,
                       PyObject *name,
                       const py_hmac_hinfo **info)
{
    const char *utf8name = PyUnicode_AsUTF8(name);
    if (utf8name == NULL) {
        goto error;
    }
    if (find_hash_info_by_utf8name(state, utf8name, info)) {
        return 1;
    }

    // try to find an alternative using the lowercase name
    PyObject *lower = PyObject_CallMethodNoArgs(name, state->str_lower);
    if (lower == NULL) {
        goto error;
    }
    const char *utf8lower = PyUnicode_AsUTF8(lower);
    if (utf8lower == NULL) {
        Py_DECREF(lower);
        goto error;
    }
    int found = find_hash_info_by_utf8name(state, utf8lower, info);
    Py_DECREF(lower);
    if (found) {
        return 1;
    }

    // try to resolve via OpenSSL EVP interface as a last resort (slow)
    return find_hash_info_by_evp_name(state, utf8name, info);

error:
    *info = NULL;
    return -1;
}

/*
 * Find the corresponding HMAC hash function static information.
 *
 * If an error occurs or if nothing can be found, this
 * returns -1 or 0 respectively, and sets 'info' to NULL.
 * Otherwise, this returns 1 and stores the result in 'info'.
 *
 * Parameters
 *
 *      state           The HMAC module state.
 *      hash_info_ref   An input to hashlib.new().
 *      info            The deduced information, if any.
 */
static int
find_hash_info_impl(hmacmodule_state *state,
                    PyObject *hash_info_ref,
                    const py_hmac_hinfo **info)
{
    if (PyUnicode_Check(hash_info_ref)) {
        return find_hash_info_by_name(state, hash_info_ref, info);
    }
    PyObject *hashlib_name = NULL;
    int rc = PyMapping_GetOptionalItem(state->hashlib_constructs_mappingproxy,
                                       hash_info_ref, &hashlib_name);
    if (rc <= 0) {
        *info = NULL;
        return rc;
    }
    rc = find_hash_info_by_name(state, hashlib_name, info);
    Py_DECREF(hashlib_name);
    return rc;
}

static const py_hmac_hinfo *
find_hash_info(hmacmodule_state *state, PyObject *hash_info_ref)
{
    const py_hmac_hinfo *info = NULL;
    int rc = find_hash_info_impl(state, hash_info_ref, &info);
    if (rc < 0) {
        assert(info == NULL);
        assert(PyErr_Occurred());
        return NULL;
    }
    if (rc == 0) {
        assert(info == NULL);
        assert(!PyErr_Occurred());
        PyErr_Format(state->hashlib_unsupported_digestmod_error,
                     "unsupported hash type: %R", hash_info_ref);
        return NULL;
    }
    return info;
}

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

// --- HMAC object ------------------------------------------------------------

/*
 * Use the HMAC information 'info' to populate
 * the corresponding fields in 'self'.
 *
 * Return 0 on success and -1 on failure.
 */
static int
hmac_set_hinfo(HMACObject *self, const py_hmac_hinfo *info)
{
    assert(info->p_name != NULL);
    self->name = Py_NewRef(info->p_name);
    self->kind = info->kind;
    self->block_size = info->block_size;
    self->digest_size = info->digest_size;
    self->api = info->api;
    return 0;
}

/*
 * Create a new internal state for the HMAC object.
 *
 * This function MUST be called after hmac_set_hinfo().
 *
 * Return 0 on success and -1 on failure.
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

    memcpy(self->state->key, key, sizeof(uint8_t) * keylen);
    self->state->keylen = keylen;

    memcpy(self->state->msg, msg, sizeof(uint8_t) * msglen);
    self->state->msglen = msglen;

    return 0;
}

/*[clinic input]
_hmac.new

    key as keyobj: object
    msg as msgobj: object(c_default="NULL") = b''
    digestmod as hash_info_ref: object(c_default="NULL") = None

Return a new HMAC object.
[clinic start generated code]*/

static PyObject *
_hmac_new_impl(PyObject *module, PyObject *keyobj, PyObject *msgobj,
               PyObject *hash_info_ref)
/*[clinic end generated code: output=7c7573a427d58758 input=f8460345fc1a26bc]*/
{
    if (hash_info_ref == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "Missing required parameter 'digestmod'.");
        return NULL;
    }

    hmacmodule_state *state = get_hmacmodule_state(module);

    const py_hmac_hinfo *info = find_hash_info(state, hash_info_ref);
    if (info == NULL) {
        assert(!PyErr_Occurred());
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
    GET_BUFFER_VIEW_OR_ERROR(keyobj, &key, goto error_on_key);
    GET_BUFFER_VIEW_OR_ERROR(msgobj, &msg, goto error_on_msg);
    int rc = hmac_new_state(self, key.buf, key.len, msg.buf, msg.len);
    PyBuffer_Release(&msg);
    PyBuffer_Release(&key);
    if (rc < 0) {
        goto error;
    }
    PyObject_GC_Track(self);
    return (PyObject *)self;

error_on_msg:
    PyBuffer_Release(&key);
error_on_key:
error:
    Py_DECREF(self);
    return NULL;
}

/*
 * Copy HMAC hash information from 'src' to 'out'.
 *
 * Return 0 on success and -1 on failure.
 */
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

/*
 * Copy HMAC internal state from 'src' to 'out'.
 *
 * Return 0 on success and -1 on failure.
 */
static int
hmac_copy_state(HMACObject *out, const HMACObject *src)
{
    const HMAC_State *st = src->state;
    return hmac_new_state(out, st->key, st->keylen, st->msg, st->msglen);
}

/*[clinic input]
_hmac.HMAC.copy

    cls: defining_class

Return a copy ("clone") of the HMAC object.
[clinic start generated code]*/

static PyObject *
_hmac_HMAC_copy_impl(HMACObject *self, PyTypeObject *cls)
/*[clinic end generated code: output=a955bfa55b65b215 input=17b2c0ad0b147e36]*/
{
    hmacmodule_state *state = get_hmacmodule_state_by_cls(cls);
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
    Py_ssize_t msglen = self->state->msglen;


#if PY_SSIZE_T_MAX > UINT32_MAX
    if (msglen > (Py_ssize_t)UINT32_MAX) {
        if (self->api.update == NULL || self->api.digest == NULL) {
            PyErr_SetNone(PyExc_NotImplementedError);
            return -1;
        }
        else {
            Py_HMAC_HACL_UPDATE_LOOP(self->api.update, self->state, msg, msglen);
            self->api.update(self->state, msg, msglen);
            self->api.digest(self->state, digest);
            return 0;
        }
    }
    else {
        // We can do one-shot encoding.
        self->api.compute(digest, key, keylen, msg, msglen);
    }
#else
    self->api.compute(digest, key, keylen, msg, msglen);
#endif
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

// --- One-shot HMAC-HASH interface -------------------------------------------

/*[clinic input]
_hmac.compute_digest

    key: object
    msg: object
    digestmod: object
    /

[clinic start generated code]*/

static PyObject *
_hmac_compute_digest_impl(PyObject *module, PyObject *key, PyObject *msg,
                          PyObject *digestmod)
/*[clinic end generated code: output=593ea8a175024c9a input=bd3be7c5b717c950]*/
{
    hmacmodule_state *state = get_hmacmodule_state(module);
    const py_hmac_hinfo *info = find_hash_info(state, digestmod);
    if (info == NULL) {
        assert(PyErr_Occurred());
        return NULL;
    }
    assert(info->api.compute_py != NULL);
    return info->api.compute_py(module, key, msg);
}

/*
 * One-shot HMAC-HASH using the given HACL_HID.
 *
 * The length of the key and message buffers must not exceed UINT32_MAX,
 * lest an OverflowError is raised. The Python implementation takes care
 * of dispatching to the OpenSSL implementation in this case.
 */
#define Py_HMAC_HACL_ONESHOT(HACL_HID, KEY, MSG)                    \
    do {                                                            \
        Py_buffer keyview, msgview;                                 \
        GET_BUFFER_VIEW_OR_ERROUT((KEY), &keyview);                 \
        if (!has_uint32_t_buffer_length(&keyview)) {                \
            PyBuffer_Release(&keyview);                             \
            PyErr_SetString(PyExc_OverflowError,                    \
                            "key length exceeds UINT32_MAX");       \
            return NULL;                                            \
        }                                                           \
        GET_BUFFER_VIEW_OR_ERROUT((MSG), &msgview);                 \
        if (!has_uint32_t_buffer_length(&msgview)) {                \
            PyBuffer_Release(&msgview);                             \
            PyBuffer_Release(&keyview);                             \
            PyErr_SetString(PyExc_OverflowError,                    \
                            "message length exceeds UINT32_MAX");   \
            return NULL;                                            \
        }                                                           \
        uint8_t out[Py_hmac_## HACL_HID ##_digest_size];            \
        Py_hmac_## HACL_HID ##_compute_func(                        \
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

// --- HMAC module methods ----------------------------------------------------

static PyMethodDef hmacmodule_methods[] = {
    _HMAC_NEW_METHODDEF
    /* one-shot HMAC functions */
    /* one-shot dispatcher */
    _HMAC_COMPUTE_DIGEST_METHODDEF
    /* one-shot methods */
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

// --- HMAC static information table ------------------------------------------

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

static void
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

// --- HMAC module initialization and finalization functions ------------------

static int
hmacmodule_init_hash_info_table(hmacmodule_state *state)
{
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
    return 0;
}

static int
hmacmodule_init_hmac_type(PyObject *hmac_module, hmacmodule_state *state)
{
    state->hmac_type = (PyTypeObject *)PyType_FromModuleAndSpec(hmac_module,
                                                                &HMAC_Type_spec,
                                                                NULL);
    if (state->hmac_type == NULL) {
        return -1;
    }
    if (PyModule_AddType(hmac_module, state->hmac_type) < 0) {
        return -1;
    }
    return 0;
}

static int
hmacmodule_init_from_hashlib(hmacmodule_state *state)
{
    PyObject *_hashlib = PyImport_ImportModule("_hashlib");
    if (_hashlib == NULL) {
        return -1;
    }
#define IMPORT_FROM_HASHLIB(VAR, NAME)                  \
    do {                                                \
        (VAR) = PyObject_GetAttrString(_hashlib, NAME); \
        if ((VAR) == NULL) {                            \
            Py_DECREF(_hashlib);                        \
            return -1;                                  \
        }                                               \
    } while (0)

    IMPORT_FROM_HASHLIB(state->hashlib_constructs_mappingproxy,
                        "_constructors");
    IMPORT_FROM_HASHLIB(state->hashlib_unsupported_digestmod_error,
                        "UnsupportedDigestmodError");
#undef IMPORT_FROM_HASHLIB
    Py_DECREF(_hashlib);
    return 0;
}

static int
hmacmodule_init_strings(hmacmodule_state *state)
{
    state->str_lower = PyUnicode_FromString("lower");
    if (state->str_lower == NULL) {
        return -1;
    }
    return 0;
}

static int
hmacmodule_exec(PyObject *module)
{
    hmacmodule_state *state = get_hmacmodule_state(module);
    if (hmacmodule_init_hash_info_table(state) < 0) {
        return -1;
    }
    if (hmacmodule_init_from_hashlib(state) < 0) {
        return -1;
    }
    if (hmacmodule_init_hmac_type(module, state) < 0) {
        return -1;
    }
    if (hmacmodule_init_strings(state) < 0) {
        return -1;
    }
    return 0;
}

static int
hmacmodule_traverse(PyObject *mod, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(mod));
    hmacmodule_state *state = get_hmacmodule_state(mod);
    Py_VISIT(state->hashlib_constructs_mappingproxy);
    Py_VISIT(state->hashlib_unsupported_digestmod_error);
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
    Py_CLEAR(state->hashlib_constructs_mappingproxy);
    Py_CLEAR(state->hashlib_unsupported_digestmod_error);
    Py_CLEAR(state->hmac_type);
    Py_CLEAR(state->str_lower);
    return 0;
}

static inline void
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
