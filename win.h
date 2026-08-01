#ifndef H_MALLOC_WIN_H
#define H_MALLOC_WIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <intrin.h>

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#define __attribute__(x)
#define __builtin_expect(x, expected) (x)
#define __builtin_expect_with_probability(x, expected, probability) (x)
#define alignas(alignment) _Alignas(alignment)

#define __ORDER_LITTLE_ENDIAN__ 1234
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__

// MSVC defines __STDC_NO_ATOMICS__ when compiling C. The allocator only needs an atomic arena
// counter and acquire/release publication of one pointer, so keep the compatibility surface
// limited to those operations. Interlocked operations provide stronger ordering than requested.
#define _Atomic volatile
typedef volatile long atomic_uint;

enum {
    memory_order_relaxed,
    memory_order_acquire,
    memory_order_release,
};

static inline unsigned msvc_atomic_fetch_add_uint(atomic_uint *object, unsigned value) {
    return (unsigned)_InterlockedExchangeAdd(object, (long)value);
}

static inline void *msvc_atomic_load_pointer(void *volatile *object) {
#if defined(_M_ARM64)
    // The published pointer resides in allocator state that becomes read-only. Use a true
    // non-writing load followed by an acquire barrier rather than an interlocked RMW operation.
    __int64 value = __iso_volatile_load64((const volatile __int64 *)object);
    __dmb(_ARM64_BARRIER_ISH);
    return (void *)(uintptr_t)value;
#else
    // Aligned pointer loads are atomic on x64, whose memory model already provides load-acquire.
    void *value = *object;
    _ReadBarrier();
    return value;
#endif
}

static inline void msvc_atomic_store_pointer(void *volatile *object, void *value) {
    (void)_InterlockedExchangePointer(object, value);
}

#define atomic_fetch_add_explicit(object, value, order) \
    ((void)(order), msvc_atomic_fetch_add_uint((object), (value)))
#define atomic_load_explicit(object, order) \
    ((void)(order), msvc_atomic_load_pointer((void *volatile *)(object)))
#define atomic_store_explicit(object, value, order) \
    ((void)(order), msvc_atomic_store_pointer((void *volatile *)(object), (value)))

static inline size_t msvc_min_size(size_t a, size_t b) {
    return a < b ? a : b;
}

static inline size_t msvc_max_size(size_t a, size_t b) {
    return a > b ? a : b;
}

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#define min(x, y) msvc_min_size((size_t)(x), (size_t)(y))
#define max(x, y) msvc_max_size((size_t)(x), (size_t)(y))

static inline bool msvc_add_overflow_size(size_t a, size_t b, size_t *result) {
    if (a > SIZE_MAX - b) {
        return true;
    }
    *result = a + b;
    return false;
}

static inline bool msvc_mul_overflow_size(size_t a, size_t b, size_t *result) {
    if (b != 0 && a > SIZE_MAX / b) {
        return true;
    }
    *result = a * b;
    return false;
}

static inline uint64_t msvc_multiply_u64(uint64_t a, uint64_t b, uint64_t *high) {
#if defined(_M_X64)
    return _umul128(a, b, high);
#elif defined(_M_ARM64)
    *high = __umulh(a, b);
    return a * b;
#else
#error "unsupported MSVC architecture"
#endif
}

#define __builtin_add_overflow(a, b, result) \
    msvc_add_overflow_size((size_t)(a), (size_t)(b), (result))
#define __builtin_mul_overflow(a, b, result) \
    msvc_mul_overflow_size((size_t)(a), (size_t)(b), (result))

static inline int msvc_builtin_ffsll(unsigned long long x) {
    unsigned long index;
    return _BitScanForward64(&index, x) ? (int)index + 1 : 0;
}

static inline int msvc_builtin_clzll(unsigned long long x) {
    unsigned long index;
    (void)_BitScanReverse64(&index, x);
    return 63 - (int)index;
}

#define __builtin_ffsll(x) msvc_builtin_ffsll((unsigned long long)(x))
#define __builtin_clzll(x) msvc_builtin_clzll((unsigned long long)(x))
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#ifdef noreturn
#pragma push_macro("noreturn")
#undef noreturn
#define H_MALLOC_RESTORE_NORETURN
#endif
#include <windows.h>
#ifdef H_MALLOC_RESTORE_NORETURN
#pragma pop_macro("noreturn")
#undef H_MALLOC_RESTORE_NORETURN
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define _SC_PAGESIZE 1
#define sysconf h_malloc_windows_sysconf

long h_malloc_windows_sysconf(int name);

struct mutex {
    SRWLOCK lock;
};

#define MUTEX_INITIALIZER {SRWLOCK_INIT}

void mutex_init(struct mutex *mutex);
void mutex_lock(struct mutex *mutex);
void mutex_unlock(struct mutex *mutex);

unsigned get_thread_arena(void);
void set_thread_arena(unsigned arena);

enum windows_resize_result {
    WINDOWS_RESIZE_NOT_POSSIBLE,
    WINDOWS_RESIZE_DONE,
    WINDOWS_RESIZE_ERROR,
};

// Attempts a page-state-only resize within an existing reservation. An unsuccessful attempt
// leaves the old payload accessible and unchanged.
enum windows_resize_result windows_try_resize_large(void *address, size_t old_size,
    size_t new_size, size_t guard_size, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
