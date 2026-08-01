#include "win.h"

#include <bcrypt.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include "h_malloc.h"
#include "memory.h"
#include "random.h"
#include "util.h"

#ifdef H_MALLOC_WINDOWS_TEST_FAULT_INJECTION
static volatile LONG reserve_failure_countdown;
static volatile LONG commit_failure_countdown;
static volatile LONG metadata_commit_failure_countdown;

EXPORT void h_malloc_test_fail_reserve(unsigned occurrence);
EXPORT void h_malloc_test_fail_commit(unsigned occurrence);
EXPORT void h_malloc_test_fail_metadata_commit(unsigned occurrence);

EXPORT void h_malloc_test_fail_reserve(unsigned occurrence) {
    InterlockedExchange(&reserve_failure_countdown, (LONG)occurrence);
}

EXPORT void h_malloc_test_fail_commit(unsigned occurrence) {
    InterlockedExchange(&commit_failure_countdown, (LONG)occurrence);
}

EXPORT void h_malloc_test_fail_metadata_commit(unsigned occurrence) {
    InterlockedExchange(&metadata_commit_failure_countdown, (LONG)occurrence);
}

static bool inject_failure(volatile LONG *countdown) {
    LONG current = InterlockedCompareExchange(countdown, 0, 0);
    while (current > 0) {
        LONG next = current - 1;
        LONG observed = InterlockedCompareExchange(countdown, next, current);
        if (observed == current) {
            return next == 0;
        }
        current = observed;
    }
    return false;
}
#endif

static bool is_memory_resource_error(DWORD error) {
    return error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_OUTOFMEMORY ||
        error == ERROR_COMMITMENT_LIMIT;
}

static bool handle_virtual_alloc_failure(void) {
    DWORD error = GetLastError();
    if (is_memory_resource_error(error)) {
        errno = ENOMEM;
        return true;
    }
    fatal_error("unexpected VirtualAlloc failure");
}

long h_malloc_windows_sysconf(int name) {
    if (unlikely(name != _SC_PAGESIZE)) {
        fatal_error("unsupported sysconf parameter");
    }
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return (long)info.dwPageSize;
}

void *memory_map(size_t size) {
#ifdef H_MALLOC_WINDOWS_TEST_FAULT_INJECTION
    if (inject_failure(&reserve_failure_countdown)) {
        errno = ENOMEM;
        return NULL;
    }
#endif
    void *p = VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_NOACCESS);
    if (unlikely(p == NULL)) {
        handle_virtual_alloc_failure();
    }
    return p;
}

bool memory_map_fixed(void *ptr, size_t size) {
    if (unlikely(!VirtualFree(ptr, size, MEM_DECOMMIT))) {
        fatal_error("VirtualFree MEM_DECOMMIT failed");
    }
    return false;
}

bool memory_unmap(void *ptr, size_t size) {
    (void)size;
    MEMORY_BASIC_INFORMATION info;
    if (unlikely(VirtualQuery(ptr, &info, sizeof(info)) != sizeof(info))) {
        fatal_error("VirtualQuery failed");
    }
    if (unlikely(info.AllocationBase == NULL || info.Type != MEM_PRIVATE)) {
        fatal_error("invalid memory mapping for release");
    }
    if (unlikely(!VirtualFree(info.AllocationBase, 0, MEM_RELEASE))) {
        fatal_error("VirtualFree MEM_RELEASE failed");
    }
    return false;
}

static bool memory_protect_committed(void *ptr, size_t size, DWORD protection) {
    DWORD old_protection;
    if (unlikely(!VirtualProtect(ptr, size, protection, &old_protection))) {
        fatal_error("VirtualProtect failed");
    }
    return false;
}

bool memory_protect_ro(void *ptr, size_t size) {
    return memory_protect_committed(ptr, size, PAGE_READONLY);
}

bool memory_protect_rw(void *ptr, size_t size) {
    bool needs_commit = false;
    char *cursor = (char *)ptr;
    size_t remaining = size;
    while (remaining != 0) {
        MEMORY_BASIC_INFORMATION info;
        if (unlikely(VirtualQuery(cursor, &info, sizeof(info)) != sizeof(info))) {
            fatal_error("VirtualQuery failed");
        }
        if (unlikely(info.State != MEM_RESERVE && info.State != MEM_COMMIT)) {
            fatal_error("invalid memory state for commit");
        }
        needs_commit |= info.State == MEM_RESERVE;

        size_t offset = (size_t)(cursor - (char *)info.BaseAddress);
        size_t available = info.RegionSize - offset;
        size_t step = min(remaining, available);
        if (unlikely(step == 0)) {
            fatal_error("invalid VirtualQuery range");
        }
        cursor += step;
        remaining -= step;
    }

    if (needs_commit) {
#ifdef H_MALLOC_WINDOWS_TEST_FAULT_INJECTION
        if (inject_failure(&commit_failure_countdown)) {
            errno = ENOMEM;
            return true;
        }
#endif
        void *p = VirtualAlloc(ptr, size, MEM_COMMIT, PAGE_READWRITE);
        if (unlikely(p == NULL)) {
            return handle_virtual_alloc_failure();
        }
        if (unlikely(p != ptr)) {
            fatal_error("VirtualAlloc MEM_COMMIT returned an unexpected address");
        }
    }
    return memory_protect_committed(ptr, size, PAGE_READWRITE);
}

enum windows_resize_result windows_try_resize_large(void *address, size_t old_size,
        size_t new_size, size_t guard_size, size_t capacity) {
    if (new_size < old_size) {
        void *new_end = (char *)address + new_size;
        size_t decommit_size = old_size - new_size + guard_size;
        return memory_map_fixed(new_end, decommit_size) ? WINDOWS_RESIZE_ERROR : WINDOWS_RESIZE_DONE;
    }
    if (new_size <= capacity) {
        void *old_end = (char *)address + old_size;
        return memory_protect_rw(old_end, new_size - old_size) ?
            WINDOWS_RESIZE_ERROR : WINDOWS_RESIZE_DONE;
    }
    return WINDOWS_RESIZE_NOT_POSSIBLE;
}

bool memory_protect_rw_metadata(void *ptr, size_t size) {
#ifdef H_MALLOC_WINDOWS_TEST_FAULT_INJECTION
    if (inject_failure(&metadata_commit_failure_countdown)) {
        errno = ENOMEM;
        return true;
    }
#endif
    return memory_protect_rw(ptr, size);
}

bool memory_purge(void *ptr, size_t size) {
    // MEM_RESET alone does not guarantee zero contents. Explicit clearing preserves the existing
    // security contract while MEM_RESET remains a best-effort working-set optimization.
    SecureZeroMemory(ptr, size);
    (void)VirtualAlloc(ptr, size, MEM_RESET, PAGE_READWRITE);
    return false;
}

bool memory_set_name(void *ptr, size_t size, const char *name) {
    (void)ptr;
    (void)size;
    (void)name;
    return false;
}

#ifndef H_MALLOC_WINDOWS_VM_TEST
void get_random_seed(void *buf, size_t size) {
    while (size) {
        ULONG chunk = size > ULONG_MAX ? ULONG_MAX : (ULONG)size;
        NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)buf, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status != 0) {
            fatal_error("BCryptGenRandom failed");
        }

        buf = (char *)buf + chunk;
        size -= chunk;
    }
}
#endif

void mutex_init(struct mutex *mutex) {
    InitializeSRWLock(&mutex->lock);
}

void mutex_lock(struct mutex *mutex) {
    AcquireSRWLockExclusive(&mutex->lock);
}

void mutex_unlock(struct mutex *mutex) {
    ReleaseSRWLockExclusive(&mutex->lock);
}

static INIT_ONCE thread_arena_once = INIT_ONCE_STATIC_INIT;
static DWORD thread_arena_index = TLS_OUT_OF_INDEXES;

static BOOL CALLBACK initialize_thread_arena(PINIT_ONCE once, PVOID parameter, PVOID *context) {
    (void)once;
    (void)parameter;
    (void)context;
    thread_arena_index = TlsAlloc();
    return thread_arena_index != TLS_OUT_OF_INDEXES;
}

unsigned get_thread_arena(void) {
    if (unlikely(!InitOnceExecuteOnce(&thread_arena_once, initialize_thread_arena, NULL, NULL))) {
        fatal_error("thread arena TLS initialization failed");
    }
    void *value = TlsGetValue(thread_arena_index);
    return value == NULL ? N_ARENA : (unsigned)(uintptr_t)value - 1;
}

void set_thread_arena(unsigned arena) {
    if (unlikely(!TlsSetValue(thread_arena_index, (void *)(uintptr_t)(arena + 1)))) {
        fatal_error("thread arena TLS assignment failed");
    }
}

static void write_stderr(const char *text) {
    HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        return;
    }

    size_t length = strlen(text);
    while (length) {
        DWORD chunk = length > MAXDWORD ? MAXDWORD : (DWORD)length;
        DWORD written;
        if (!WriteFile(handle, text, chunk, &written, NULL) || written == 0) {
            return;
        }
        text += written;
        length -= written;
    }
}

COLD noreturn void fatal_error(const char *s) {
    write_stderr("fatal allocator error: ");
    write_stderr(s);
    write_stderr("\n");

    RaiseFailFastException(NULL, NULL, 0);
    (void)TerminateProcess(GetCurrentProcess(), 0xC0000409u);
    for (;;) {
    }
}

#ifndef H_MALLOC_WINDOWS_VM_TEST
EXPORT void h_cfree(void *ptr) {
    h_free(ptr);
}

EXPORT void *h_memalign(size_t alignment, size_t size) {
    return h_aligned_alloc(alignment, size);
}
#endif
