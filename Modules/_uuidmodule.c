/*
 * Python UUID module that wraps libuuid or Windows rpcrt4.dll.
 * DCE compatible Universally Unique Identifier library.
 */

/* This module needs some built-in functions such as _PyOS_URandom(). */
#ifndef Py_BUILD_CORE_BUILTIN
#  define Py_BUILD_CORE_MODULE 1
#endif

#include "Python.h"
#include "pycore_long.h"                    // _PyLong_FromBytes()
#include "pycore_pylifecycle.h"             // _PyOS_URandom

#if defined(HAVE_UUID_H)
  // AIX, FreeBSD, libuuid with pkgconf
  #include <uuid.h>
#elif defined(HAVE_UUID_UUID_H)
  // libuuid without pkgconf
  #include <uuid/uuid.h>
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>             // getpid()
#endif
#ifdef HAVE_PROCESS_H
#  include <process.h>            // getpid() on Windows
#endif

#ifdef MS_WINDOWS
#include <rpc.h>
#endif

#ifndef MS_WINDOWS

static PyObject *
py_uuid_generate_time_safe(PyObject *Py_UNUSED(context),
                           PyObject *Py_UNUSED(ignored))
{
    uuid_t uuid;
#ifdef HAVE_UUID_GENERATE_TIME_SAFE
    int res;

    res = uuid_generate_time_safe(uuid);
    return Py_BuildValue("y#i", (const char *) uuid, sizeof(uuid), res);
#elif defined(HAVE_UUID_CREATE)
    uint32_t status;
    uuid_create(&uuid, &status);
# if defined(HAVE_UUID_ENC_BE)
    unsigned char buf[sizeof(uuid)];
    uuid_enc_be(buf, &uuid);
    return Py_BuildValue("y#i", buf, sizeof(uuid), (int) status);
# else
    return Py_BuildValue("y#i", (const char *) &uuid, sizeof(uuid), (int) status);
# endif /* HAVE_UUID_CREATE */
#else /* HAVE_UUID_GENERATE_TIME_SAFE */
    uuid_generate_time(uuid);
    return Py_BuildValue("y#O", (const char *) uuid, sizeof(uuid), Py_None);
#endif /* HAVE_UUID_GENERATE_TIME_SAFE */
}

#else /* MS_WINDOWS */

static PyObject *
py_UuidCreate(PyObject *Py_UNUSED(context),
              PyObject *Py_UNUSED(ignored))
{
    UUID uuid;
    RPC_STATUS res;

    Py_BEGIN_ALLOW_THREADS
    res = UuidCreateSequential(&uuid);
    Py_END_ALLOW_THREADS

    switch (res) {
    case RPC_S_OK:
    case RPC_S_UUID_LOCAL_ONLY:
    case RPC_S_UUID_NO_ADDRESS:
        /*
        All success codes, but the latter two indicate that the UUID is random
        rather than based on the MAC address. If the OS can't figure this out,
        neither can we, so we'll take it anyway.
        */
        return Py_BuildValue("y#", (const char *)&uuid, sizeof(uuid));
    }
    PyErr_SetFromWindowsErr(res);
    return NULL;
}

static int
py_windows_has_stable_node(void)
{
    UUID uuid;
    RPC_STATUS res;
    Py_BEGIN_ALLOW_THREADS
    res = UuidCreateSequential(&uuid);
    Py_END_ALLOW_THREADS
    return res == RPC_S_OK;
}
#endif /* MS_WINDOWS */

// UUID Structure per RFC 9562:
//
// A UUID is 128 bits (16 bytes) represented as:
//
// String:       xx xx xx xx - xx xx - Mx xx - Nx xx - xx xx xx xx xx xx
// Byte pos:     0  1  2  3    4  5    6  7    8  9    10 11 12 13 14 15
//               ^^^^^^^^^^^   ^^^^^   ^^^^^   ^^^^^   ^^^^^^^^^^^^^^^^^
//                time_low      mid     hi      seq          node
//
// Byte Layout (big-endian):
//
// Bytes 0-3:   time_low                 (32 bits)
// Bytes 4-5:   time_mid                 (16 bits)
// Bytes 6-7:   time_hi_and_version      (16 bits)
// Bytes 8-9:   clock_seq_and_variant    (16 bits)
// Bytes 10-15: node                     (48 bits)
//
// Note that the time attributes are only relevant to versions 1, 6 and 7.
//
// Version field is located in byte 6; most significant 4 bits:
//
// Variant field is located in byte 8; most significant variable bits:
//   0xxx: Reserved for NCS compatibility
//   10xx: RFC 4122/9562 (standard)
//   110x: Reserved for Microsoft compatibility
//   111x: Reserved for future definition

#define RANDOM_BUF_SIZE     256

/* State of the _uuid module */
typedef struct {
    PyObject *hook_os_urandom;
    PyObject *hook_fetch_time;

    // RANDOM_BUF_SIZE as a PyObject
    PyObject *random_buf_size;

    // We overfetch entropy to speed up successive UUID generations.
    // The 'random_last_idx' value holds the number consumed bytes
    // and are guaranteed to be in [0, RANDOM_BUF_SIZE).
    uint8_t random_buf[RANDOM_BUF_SIZE];
    uint64_t random_last_idx;
    uint64_t random_last_pid;

    // UUID v7 state
    uint64_t last_timestamp_v7;
    uint64_t last_counter_v7;
    uint8_t last_timestamp_v7_init;
} uuidmodule_state;

/*[clinic input]
module _uuid
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=7cbed123a45a3859]*/

#include "clinic/_uuidmodule.c.h"

static struct PyModuleDef uuidmodule;

static inline uuidmodule_state *
get_module_state(PyObject *mod)
{
    uuidmodule_state *state = PyModule_GetState(mod);
    assert(state != NULL);
    return state;
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

static inline uint64_t
get_current_process_id(void)
{
#if !defined(MS_WINDOWS) || defined(MS_WINDOWS_DESKTOP) || defined(MS_WINDOWS_SYSTEM)
    return (uint64_t)getpid();
#else
    return (uint64_t)GetCurrentProcessId();
#endif
}

static inline int
fetch_current_time(uuidmodule_state *st, PyTime_t *time)
{
    if (st->hook_fetch_time == NULL) {
        return PyTime_Time(time);
    }

    PyObject *ret = PyObject_CallNoArgs(st->hook_fetch_time);
    if (ret == NULL) {
        return -1;
    }

    if (!PyLong_CheckExact(ret)) {
        Py_DECREF(ret);
        PyErr_SetString(PyExc_ValueError, "time() hook must return an int");
        return -1;
    }

    int res = PyLong_AsInt64(ret, time);
    Py_DECREF(ret);
    return res;
}

/*
 * Fill a buffer with 'size' random bytes.
 *
 * Overfetching & caching entropy improves the performance 10x.
 * There's a precedent with NodeJS doing exact same thing for
 * improving performance of their UUID implementation.
 */
static int
gen_random_lock_held(uuidmodule_state *state, uint8_t *bytes, Py_ssize_t size)
{
    assert(state->random_last_idx < RANDOM_BUF_SIZE);
    uint64_t pid = get_current_process_id();
    if (pid != state->random_last_pid) {
        // Invalidate cache after fork so to avoid sharing entropy.
        state->random_last_pid = pid;
        state->random_last_idx = RANDOM_BUF_SIZE;
    }

    if (state->random_last_idx + size < RANDOM_BUF_SIZE) {
        memcpy(bytes, state->random_buf + state->random_last_idx, size);
        state->random_last_idx += size;
    }
    else {
        if (state->random_last_idx < RANDOM_BUF_SIZE) {
            // We exhaustively consume cached entropy. We do that
            // because we have tests that compare Python and C
            // implementations and it's important that they see incoming
            // entropy as a continuous stream.
            //
            // The overhead here must be negligible, but we want the same
            // code to be run in production and in tests.
            Py_ssize_t partial = RANDOM_BUF_SIZE - state->random_last_idx;
            memcpy(bytes, state->random_buf + state->random_last_idx, partial);
            bytes += partial;
            size -= partial;
        }

        // By-pass PyObject conversion happening in os.urandom()
        // or use the corresponding hook defined on this module
        // to update our bytes pool.
        if (state->hook_os_urandom == NULL) {
            if (_PyOS_URandom(state->random_buf, RANDOM_BUF_SIZE) < 0) {
                return -1;
            }
        }
        else {
            PyObject *buf = PyObject_CallOneArg(state->hook_os_urandom,
                                                state->random_buf_size);
            if (buf == NULL) {
                return -1;
            }
            if (!PyBytes_CheckExact(buf)) {
                PyErr_SetString(PyExc_ValueError,
                                "random() hook must return a bytes object");
                Py_DECREF(buf);
                return -1;
            }
            if (PyBytes_GET_SIZE(buf) != (Py_ssize_t)RANDOM_BUF_SIZE) {
                PyErr_Format(PyExc_ValueError,
                             "random() hook must return exactly %d bytes",
                             RANDOM_BUF_SIZE);
                Py_DECREF(buf);
                return -1;
            }
            memcpy(state->random_buf, PyBytes_AsString(buf), RANDOM_BUF_SIZE);
            Py_DECREF(buf);
        }

        memcpy(bytes, state->random_buf, size);
        state->random_last_idx = size;
    }

    return 0;
}

// ----------------------------------------------------------------------------
// UUIDv7 generation
// ----------------------------------------------------------------------------

static inline int
uuid7_get_counter_and_tail(uuidmodule_state *st,
                           uint64_t *counter, uint8_t *tail)
{
    struct {
        uint16_t hi;
        uint32_t lo;
        uint32_t tail;
    } buf;
    if (gen_random_lock_held(st, (uint8_t *)&buf, sizeof(buf)) < 0) {
        return -1;
    }

    *counter = (((uint64_t)(buf.hi & 0x1FF) << 32) | buf.lo) & 0x1FFFFFFFFFF;
    *tail = buf.tail;
    return 0;
}

/*[clinic input]
@critical_section
_uuid.uuid7_int

Generate a UUID from a Unix timestamp in milliseconds and random bits.

UUIDv7 objects feature monotonicity within a millisecond.
[clinic start generated code]*/

static PyObject *
_uuid_uuid7_int_impl(PyObject *module)
/*[clinic end generated code: output=dfb81db16a5c8f7b input=a303326e794e089f]*/
{
    uint8_t bytes[16];
    uint8_t *tail = bytes + 12;
    uint64_t timestamp_ms, counter;
    uuidmodule_state *state = get_module_state(module);

    PyTime_t timestamp;
    if (fetch_current_time(state, &timestamp) < 0) {
        return NULL;
    }
    timestamp_ms = (uint64_t)(timestamp / 1000000);

    if (!state->last_timestamp_v7_init || timestamp_ms > state->last_timestamp_v7) {
        if (uuid7_get_counter_and_tail(state, &counter, tail) < 0) {
            return NULL;
        }
    } else {
        // TODO(picnizx): decide how to handle overflows more generally.
        // See: https://github.com/python/cpython/issues/138862.
        if (timestamp_ms < state->last_timestamp_v7) {
            timestamp_ms = state->last_timestamp_v7 + 1;
        }
        // advance the 42-bit counter
        counter = state->last_counter_v7 + 1;
        if (counter > 0x3FFFFFFFFFF) {
            // advance the 48-bit timestamp
            timestamp_ms += 1;
            if (uuid7_get_counter_and_tail(state, &counter, tail) < 0) {
                return NULL;
            }
        } else {
            // This is the common fast path, we only need 4 bytes of entropy.
            if (gen_random_lock_held(state, tail, 4) < 0) {
                return NULL;
            }
        }
    }

    timestamp_ms &= 0xFFFFFFFFFFFF;
    bytes[0] = (uint8_t)(timestamp_ms >> 40);
    bytes[1] = (uint8_t)(timestamp_ms >> 32);
    bytes[2] = (uint8_t)(timestamp_ms >> 24);
    bytes[3] = (uint8_t)(timestamp_ms >> 16);
    bytes[4] = (uint8_t)(timestamp_ms >> 8);
    bytes[5] = timestamp_ms;

    uint16_t counter_hi = (counter >> 30) & 0x0FFF;
    bytes[6] = 0x70 | ((counter_hi >> 8));  // Version 7 = 0111
    bytes[7] = (uint8_t)counter_hi;

    uint16_t counter_mid = (counter >> 16) & 0x3FFF;
    bytes[8] = 0x80 | (counter_mid >> 8);  // Variant = 10
    bytes[9] = (uint8_t)counter_mid;

    uint16_t counter_lo = counter & 0xFFFF;
    bytes[10] = counter_lo >> 8;
    bytes[11] = (uint8_t)counter_lo;

    state->last_timestamp_v7_init = 1;
    state->last_timestamp_v7 = timestamp_ms;
    state->last_counter_v7 = counter;

    return _PyLong_FromByteArray((const unsigned char *)bytes, 16, 0, 0);
}

static int
uuidmodule_traverse(PyObject *mod, visitproc visit, void *arg)
{
    uuidmodule_state *state = get_module_state(mod);
    Py_VISIT(state->hook_os_urandom);
    Py_VISIT(state->hook_fetch_time);
    Py_VISIT(state->random_buf_size);
    return 0;
}

static int
uuidmodule_clear(PyObject *mod)
{
    uuidmodule_state *state = get_module_state(mod);
    Py_CLEAR(state->hook_os_urandom);
    Py_CLEAR(state->hook_fetch_time);
    Py_CLEAR(state->random_buf_size);
    return 0;
}

static void
uuidmodule_free(void *mod)
{
    (void)uuidmodule_clear((PyObject *)mod);
}

static int
uuidmodule_exec(PyObject *module)
{
#define ADD_INT(NAME, VALUE)                                        \
    do {                                                            \
        if (PyModule_AddIntConstant(module, (NAME), (VALUE)) < 0) { \
           return -1;                                               \
        }                                                           \
    } while (0)

    assert(sizeof(uuid_t) == 16);
#if defined(MS_WINDOWS)
    ADD_INT("has_uuid_generate_time_safe", 0);
#elif defined(HAVE_UUID_GENERATE_TIME_SAFE)
    ADD_INT("has_uuid_generate_time_safe", 1);
#else
    ADD_INT("has_uuid_generate_time_safe", 0);
#endif

#if defined(MS_WINDOWS)
    ADD_INT("has_stable_extractable_node", py_windows_has_stable_node());
#elif defined(HAVE_UUID_GENERATE_TIME_SAFE_STABLE_MAC)
    ADD_INT("has_stable_extractable_node", 1);
#else
    ADD_INT("has_stable_extractable_node", 0);
#endif

#undef ADD_INT
    return 0;
}

static PyMethodDef uuidmodule_methods[] = {
    _UUID_UUID7_INT_METHODDEF
#if defined(HAVE_UUID_UUID_H) || defined(HAVE_UUID_H)
    {"generate_time_safe", py_uuid_generate_time_safe, METH_NOARGS, NULL},
#endif
#if defined(MS_WINDOWS)
    {"UuidCreate", py_UuidCreate, METH_NOARGS, NULL},
#endif
    {NULL, NULL, 0, NULL}           /* sentinel */
};

static PyModuleDef_Slot uuidmodule_slots[] = {
    {Py_mod_exec, uuidmodule_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef uuidmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_uuid",
    .m_size = sizeof(uuidmodule_state),
    .m_methods = uuidmodule_methods,
    .m_traverse = uuidmodule_traverse,
    .m_clear = uuidmodule_clear,
    .m_slots = uuidmodule_slots,
    .m_free = uuidmodule_free,
};

PyMODINIT_FUNC
PyInit__uuid(void)
{
    return PyModuleDef_Init(&uuidmodule);
}
