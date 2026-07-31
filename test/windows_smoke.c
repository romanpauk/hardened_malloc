#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "h_malloc.h"

#define THREAD_COUNT 8
#define THREAD_ITERATIONS 2000
#define TEST_TIMEOUT_MS 30000

static HANDLE allocation_start_event;
static HANDLE allocation_ready_event;
static volatile LONG allocation_workers_ready;

static bool bytes_equal(const unsigned char *p, size_t size, unsigned char value) {
    for (size_t i = 0; i < size; i++) {
        if (p[i] != value) {
            return false;
        }
    }
    return true;
}

static DWORD WINAPI allocation_worker(void *argument) {
    uintptr_t thread_number = (uintptr_t)argument;

    if (InterlockedIncrement(&allocation_workers_ready) == THREAD_COUNT && !SetEvent(allocation_ready_event)) {
        return 4;
    }
    if (WaitForSingleObject(allocation_start_event, TEST_TIMEOUT_MS) != WAIT_OBJECT_0) {
        return 5;
    }

    for (size_t i = 0; i < THREAD_ITERATIONS; i++) {
        size_t size = ((i + 1) * (thread_number + 17)) % (128 * 1024) + 1;
        unsigned char pattern = (unsigned char)(i + thread_number);
        unsigned char *p = h_malloc(size);
        if (p == NULL) {
            return 1;
        }
        memset(p, pattern, size);

        size_t new_size = size + 16 * 1024;
        unsigned char *q = h_realloc(p, new_size);
        if (q == NULL) {
            h_free(p);
            return 2;
        }
        for (size_t j = 0; j < size; j++) {
            if (q[j] != pattern) {
                h_free(q);
                return 3;
            }
        }
        h_free(q);
    }

    return 0;
}

static int test_large_reallocation(void) {
    const size_t capacity = 2 * 1024 * 1024;
    const size_t shrunk_size = 1024 * 1024;
    const size_t beyond_capacity = 3 * 1024 * 1024;
    unsigned char *p = h_malloc(capacity);
    if (p == NULL) {
        return 20;
    }
    memset(p, 0xa5, capacity);

    unsigned char *shrunk = h_realloc(p, shrunk_size);
    if (shrunk != p) {
        h_free(shrunk == NULL ? p : shrunk);
        return 21;
    }

    unsigned char *grown = h_realloc(shrunk, capacity);
    if (grown != p) {
        h_free(grown == NULL ? shrunk : grown);
        return 22;
    }
    if (!bytes_equal(grown, shrunk_size, 0xa5)) {
        h_free(grown);
        return 23;
    }
    if (!bytes_equal(grown + shrunk_size, capacity - shrunk_size, 0)) {
        h_free(grown);
        return 24;
    }

    memset(grown, 0x3c, capacity);
    unsigned char *moved = h_realloc(grown, beyond_capacity);
    if (moved == NULL) {
        h_free(grown);
        return 25;
    }
    if (moved == grown) {
        h_free(moved);
        return 26;
    }
    if (!bytes_equal(moved, capacity, 0x3c)) {
        h_free(moved);
        return 27;
    }
    h_free(moved);
    return 0;
}

static int test_reallocation_transitions(void) {
    unsigned char *p = h_realloc(NULL, 17);
    if (p == NULL) {
        return 50;
    }
    memset(p, 0x51, 17);

    unsigned char *same_class = h_realloc(p, 20);
    if (same_class == NULL) {
        h_free(p);
        return 51;
    }
    if (same_class != p || !bytes_equal(same_class, 17, 0x51)) {
        h_free(same_class);
        return 52;
    }

    unsigned char *different_small_class = h_realloc(same_class, 4096);
    if (different_small_class == NULL) {
        h_free(same_class);
        return 53;
    }
    if (different_small_class == same_class || !bytes_equal(different_small_class, 17, 0x51)) {
        h_free(different_small_class);
        return 54;
    }
    memset(different_small_class, 0x52, 4096);

    unsigned char *large = h_realloc(different_small_class, 256 * 1024);
    if (large == NULL) {
        h_free(different_small_class);
        return 55;
    }
    if (large == different_small_class || !bytes_equal(large, 4096, 0x52)) {
        h_free(large);
        return 56;
    }

    unsigned char *small = h_realloc(large, 64);
    if (small == NULL) {
        h_free(large);
        return 57;
    }
    if (small == large || !bytes_equal(small, 64, 0x52)) {
        h_free(small);
        return 58;
    }

    unsigned char *zero_size = h_realloc(small, 0);
    if (zero_size != NULL) {
        h_free(zero_size);
    }
    return 0;
}

static int test_reallocation_boundary(void) {
#if CONFIG_EXTENDED_SIZE_CLASSES
    const size_t maximum_small_size = 128 * 1024;
#else
    const size_t maximum_small_size = 16 * 1024;
#endif
    const size_t small_request = maximum_small_size - 64;
    const size_t large_request = maximum_small_size + 1;

    unsigned char *p = h_malloc(small_request);
    if (p == NULL) {
        return 60;
    }
    memset(p, 0x61, small_request);

    unsigned char *q = h_realloc(p, large_request);
    if (q == NULL) {
        h_free(p);
        return 61;
    }
    if (q == p || !bytes_equal(q, small_request, 0x61)) {
        h_free(q);
        return 62;
    }
    h_free(q);
    return 0;
}

static int test_reallocation_failure(void) {
    const size_t size = 4096;
    unsigned char *p = h_malloc(size);
    if (p == NULL) {
        return 70;
    }
    memset(p, 0x71, size);

    volatile size_t impossible_size = SIZE_MAX;
    errno = 0;
    void *q = h_realloc(p, impossible_size);
    if (q != NULL || errno != ENOMEM || !bytes_equal(p, size, 0x71)) {
        h_free(q == NULL ? p : q);
        return 71;
    }

    errno = 0;
    q = h_reallocarray(p, impossible_size, 2);
    if (q != NULL || errno != ENOMEM || !bytes_equal(p, size, 0x71)) {
        h_free(q == NULL ? p : q);
        return 72;
    }
    h_free(p);
    return 0;
}

static int test_aligned_allocation(void) {
    const size_t alignment = 1024 * 1024;
    const size_t size = 2 * 1024 * 1024;
    unsigned char *p = h_aligned_alloc(alignment, size);
    if (p == NULL) {
        return 30;
    }
    if ((uintptr_t)p % alignment != 0) {
        h_free(p);
        return 31;
    }
    p[0] = 1;
    p[size - 1] = 2;
    h_free(p);
    return 0;
}

static int test_legacy_allocation_compatibility(void) {
    const size_t page_size = 4096;
    unsigned char *p = h_valloc(17);
    if (p == NULL || (uintptr_t)p % page_size != 0) {
        h_cfree(p);
        return 80;
    }
    p[0] = 0x80;
    h_cfree(p);

    p = h_pvalloc(page_size + 1);
    if (p == NULL || (uintptr_t)p % page_size != 0 ||
            h_malloc_usable_size(p) < page_size * 2) {
        h_free(p);
        return 81;
    }
    p[page_size * 2 - 1] = 0x81;
    h_free(p);

    errno = 0;
    p = h_pvalloc(SIZE_MAX);
    if (p != NULL || errno != ENOMEM) {
        h_free(p);
        return 82;
    }
    return 0;
}

static int test_concurrent_allocations(void) {
    HANDLE threads[THREAD_COUNT];
    allocation_start_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (allocation_start_event == NULL) {
        return 40;
    }
    allocation_ready_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (allocation_ready_event == NULL) {
        CloseHandle(allocation_start_event);
        return 41;
    }
    allocation_workers_ready = 0;

    size_t created = 0;
    for (uintptr_t i = 0; i < THREAD_COUNT; i++) {
        threads[i] = CreateThread(NULL, 0, allocation_worker, (void *)i, 0, NULL);
        if (threads[i] == NULL) {
            SetEvent(allocation_start_event);
            for (size_t j = 0; j < created; j++) {
                CloseHandle(threads[j]);
            }
            CloseHandle(allocation_ready_event);
            CloseHandle(allocation_start_event);
            return 42;
        }
        created++;
    }

    if (WaitForSingleObject(allocation_ready_event, TEST_TIMEOUT_MS) != WAIT_OBJECT_0) {
        SetEvent(allocation_start_event);
        for (size_t i = 0; i < THREAD_COUNT; i++) {
            CloseHandle(threads[i]);
        }
        CloseHandle(allocation_ready_event);
        CloseHandle(allocation_start_event);
        return 43;
    }
    if (!SetEvent(allocation_start_event)) {
        for (size_t i = 0; i < THREAD_COUNT; i++) {
            CloseHandle(threads[i]);
        }
        CloseHandle(allocation_ready_event);
        CloseHandle(allocation_start_event);
        return 44;
    }

    if (WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, TEST_TIMEOUT_MS) != WAIT_OBJECT_0) {
        for (size_t i = 0; i < THREAD_COUNT; i++) {
            CloseHandle(threads[i]);
        }
        CloseHandle(allocation_ready_event);
        CloseHandle(allocation_start_event);
        return 45;
    }
    int result = 0;
    for (size_t i = 0; i < THREAD_COUNT; i++) {
        DWORD thread_result;
        if (!GetExitCodeThread(threads[i], &thread_result) || thread_result != 0) {
            result = 46;
        }
        CloseHandle(threads[i]);
    }
    CloseHandle(allocation_ready_event);
    CloseHandle(allocation_start_event);
    allocation_ready_event = NULL;
    allocation_start_event = NULL;
    return result;
}

int main(void) {
    // This must run first so all workers race the allocator's lazy initialization path.
    int result = test_concurrent_allocations();
    if (result == 0) {
        result = test_large_reallocation();
    }
    if (result == 0) {
        result = test_reallocation_transitions();
    }
    if (result == 0) {
        result = test_reallocation_boundary();
    }
    if (result == 0) {
        result = test_reallocation_failure();
    }
    if (result == 0) {
        result = test_aligned_allocation();
    }
    if (result == 0) {
        result = test_legacy_allocation_compatibility();
    }
    return result;
}
