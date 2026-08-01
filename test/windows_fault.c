#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "h_malloc.h"

#define STATUS_ACCESS_VIOLATION_VALUE ((DWORD)0xC0000005u)
#define STATUS_STACK_BUFFER_OVERRUN_VALUE ((DWORD)0xC0000409u)
#define STATUS_FAIL_FAST_EXCEPTION_VALUE ((DWORD)0xC0000602u)

#ifdef H_MALLOC_WINDOWS_TEST_FAULT_INJECTION
__declspec(dllimport) void h_malloc_test_fail_reserve(unsigned occurrence);
__declspec(dllimport) void h_malloc_test_fail_commit(unsigned occurrence);
__declspec(dllimport) void h_malloc_test_fail_metadata_commit(unsigned occurrence);
#endif

typedef int (*probe_function)(void);

struct probe {
    const char *name;
    probe_function function;
    DWORD expected_status;
    const char *expected_diagnostic;
};

static int allocation_failed(void) {
    return 100;
}

static int probe_invalid_free(void) {
    void *p = h_malloc(16);
    if (p == NULL) {
        return allocation_failed();
    }
    h_free(p);

    uintptr_t value = 0;
    h_free(&value);
    return 101;
}

static int probe_shrunk_large_tail(void) {
    unsigned char *p = h_malloc(2 * 1024 * 1024);
    if (p == NULL) {
        return allocation_failed();
    }
    unsigned char *shrunk = h_realloc(p, 1024 * 1024);
    if (shrunk != p) {
        h_free(shrunk == NULL ? p : shrunk);
        return 114;
    }
    volatile unsigned char *address = shrunk + h_malloc_usable_size(shrunk);
    *address = 1;
    return 115;
}

static int probe_grown_large_guard(void) {
    unsigned char *p = h_malloc(2 * 1024 * 1024);
    if (p == NULL) {
        return allocation_failed();
    }
    unsigned char *shrunk = h_realloc(p, 1024 * 1024);
    if (shrunk != p) {
        h_free(shrunk == NULL ? p : shrunk);
        return 116;
    }
    unsigned char *grown = h_realloc(shrunk, 2 * 1024 * 1024);
    if (grown != p) {
        h_free(grown == NULL ? shrunk : grown);
        return 117;
    }
    volatile unsigned char *address = grown + h_malloc_usable_size(grown);
    *address = 1;
    return 118;
}

#ifdef H_MALLOC_WINDOWS_TEST_FAULT_INJECTION
static int probe_init_rng_reserve_failure(void) {
    h_malloc_test_fail_reserve(1);
    (void)h_malloc(16);
    return 120;
}

static int probe_init_state_reserve_failure(void) {
    h_malloc_test_fail_reserve(2);
    (void)h_malloc(16);
    return 121;
}

static int probe_init_rng_commit_failure(void) {
    h_malloc_test_fail_commit(1);
    (void)h_malloc(16);
    return 122;
}

static int probe_init_state_commit_failure(void) {
    h_malloc_test_fail_metadata_commit(1);
    (void)h_malloc(16);
    return 123;
}

static int initialize_allocator(void) {
    void *p = h_malloc(16);
    if (p == NULL) {
        return 1;
    }
    h_free(p);
    return 0;
}

static int probe_large_reserve_failure(void) {
    if (initialize_allocator()) {
        return 124;
    }
    h_malloc_test_fail_reserve(1);
    errno = 0;
    void *p = h_malloc(256 * 1024);
    if (p != NULL) {
        h_free(p);
        return 125;
    }
    return errno == ENOMEM ? 0 : 126;
}

static int probe_large_commit_failure(void) {
    if (initialize_allocator()) {
        return 127;
    }
    h_malloc_test_fail_commit(1);
    errno = 0;
    void *p = h_malloc(256 * 1024);
    if (p != NULL) {
        h_free(p);
        return 128;
    }
    return errno == ENOMEM ? 0 : 129;
}

static int probe_realloc_commit_failure(void) {
    const size_t initial_size = 2 * 1024 * 1024;
    const size_t shrunk_size = 1024 * 1024;
    unsigned char *p = h_malloc(initial_size);
    if (p == NULL) {
        return 130;
    }
    memset(p, 0x7a, shrunk_size);
    unsigned char *shrunk = h_realloc(p, shrunk_size);
    if (shrunk != p) {
        h_free(shrunk == NULL ? p : shrunk);
        return 131;
    }

    h_malloc_test_fail_commit(1);
    errno = 0;
    unsigned char *grown = h_realloc(shrunk, initial_size);
    if (grown != NULL) {
        h_free(grown);
        return 132;
    }
    if (errno != ENOMEM || h_malloc_usable_size(shrunk) != shrunk_size) {
        h_free(shrunk);
        return 133;
    }
    for (size_t i = 0; i < shrunk_size; i++) {
        if (shrunk[i] != 0x7a) {
            h_free(shrunk);
            return 134;
        }
    }
    h_free(shrunk);
    return 0;
}

static int probe_realloc_copy_reserve_failure(void) {
    const size_t initial_size = 2 * 1024 * 1024;
    unsigned char *p = h_malloc(initial_size);
    if (p == NULL) {
        return 135;
    }
    memset(p, 0x7b, initial_size);

    h_malloc_test_fail_reserve(1);
    errno = 0;
    unsigned char *grown = h_realloc(p, 3 * 1024 * 1024);
    if (grown != NULL) {
        h_free(grown);
        return 136;
    }
    if (errno != ENOMEM || h_malloc_usable_size(p) != initial_size) {
        h_free(p);
        return 137;
    }
    for (size_t i = 0; i < initial_size; i++) {
        if (p[i] != 0x7b) {
            h_free(p);
            return 138;
        }
    }
    h_free(p);
    return 0;
}

static int probe_region_table_growth_failure(void) {
    enum { ALLOCATION_COUNT_BEFORE_GROWTH = 97 };
    void *allocations[ALLOCATION_COUNT_BEFORE_GROWTH];
    size_t allocated = 0;
    for (; allocated < ALLOCATION_COUNT_BEFORE_GROWTH; allocated++) {
        allocations[allocated] = h_malloc(256 * 1024);
        if (allocations[allocated] == NULL) {
            break;
        }
    }
    if (allocated != ALLOCATION_COUNT_BEFORE_GROWTH) {
        for (size_t i = 0; i < allocated; i++) {
            h_free(allocations[i]);
        }
        return 139;
    }

    h_malloc_test_fail_metadata_commit(1);
    errno = 0;
    void *p = h_malloc(256 * 1024);
    int result = p == NULL && errno == ENOMEM ? 0 : 140;
    if (p != NULL) {
        h_free(p);
    }
    for (size_t i = 0; i < allocated; i++) {
        ((volatile unsigned char *)allocations[i])[0] = (unsigned char)i;
        h_free(allocations[i]);
    }
    return result;
}
#endif

static const struct probe probes[] = {
    {"invalid-free", probe_invalid_free, STATUS_FAIL_FAST_EXCEPTION_VALUE,
     "fatal allocator error: invalid free\n"},
    {"shrunk-large-tail", probe_shrunk_large_tail, STATUS_ACCESS_VIOLATION_VALUE, ""},
    {"grown-large-guard", probe_grown_large_guard, STATUS_ACCESS_VIOLATION_VALUE, ""},
#ifdef H_MALLOC_WINDOWS_TEST_FAULT_INJECTION
    {"init-rng-reserve-failure", probe_init_rng_reserve_failure, STATUS_FAIL_FAST_EXCEPTION_VALUE,
     "fatal allocator error: failed to allocate init rng\n"},
    {"init-state-reserve-failure", probe_init_state_reserve_failure, STATUS_FAIL_FAST_EXCEPTION_VALUE,
     "fatal allocator error: failed to reserve allocator state\n"},
    {"init-rng-commit-failure", probe_init_rng_commit_failure, STATUS_FAIL_FAST_EXCEPTION_VALUE,
     "fatal allocator error: failed to allocate init rng\n"},
    {"init-state-commit-failure", probe_init_state_commit_failure, STATUS_FAIL_FAST_EXCEPTION_VALUE,
     "fatal allocator error: failed to unprotect allocator state\n"},
    {"large-reserve-failure", probe_large_reserve_failure, 0, ""},
    {"large-commit-failure", probe_large_commit_failure, 0, ""},
    {"realloc-commit-failure", probe_realloc_commit_failure, 0, ""},
    {"realloc-copy-reserve-failure", probe_realloc_copy_reserve_failure, 0, ""},
    {"region-table-growth-failure", probe_region_table_growth_failure, 0, ""},
#endif
};

static const struct probe *find_probe(const char *name) {
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        if (strcmp(name, probes[i].name) == 0) {
            return &probes[i];
        }
    }
    return NULL;
}

static int is_expected_status(DWORD actual, DWORD expected) {
    if (actual == expected) {
        return 1;
    }
    return expected == STATUS_FAIL_FAST_EXCEPTION_VALUE && actual == STATUS_STACK_BUFFER_OVERRUN_VALUE;
}

static int run_child(const char *module_path, const struct probe *probe) {
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security),
        .lpSecurityDescriptor = NULL,
        .bInheritHandle = TRUE,
    };
    HANDLE stderr_read;
    HANDLE stderr_write;
    if (!CreatePipe(&stderr_read, &stderr_write, &security, 0)) {
        fprintf(stderr, "%s: CreatePipe failed: %lu\n", probe->name, GetLastError());
        return 1;
    }
    if (!SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0)) {
        fprintf(stderr, "%s: SetHandleInformation failed: %lu\n", probe->name, GetLastError());
        CloseHandle(stderr_read);
        CloseHandle(stderr_write);
        return 1;
    }

    STARTUPINFOA startup = {
        .cb = sizeof(startup),
        .dwFlags = STARTF_USESTDHANDLES,
        .hStdInput = GetStdHandle(STD_INPUT_HANDLE),
        .hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE),
        .hStdError = stderr_write,
    };
    PROCESS_INFORMATION process;
    char command_line[MAX_PATH + 128];
    int length = snprintf(command_line, sizeof(command_line), "\"%s\" --probe %s", module_path, probe->name);
    if (length < 0 || (size_t)length >= sizeof(command_line)) {
        fprintf(stderr, "%s: executable path is too long\n", probe->name);
        CloseHandle(stderr_read);
        CloseHandle(stderr_write);
        return 1;
    }

    BOOL created = CreateProcessA(module_path, command_line, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup,
                                  &process);
    CloseHandle(stderr_write);
    if (!created) {
        fprintf(stderr, "%s: CreateProcess failed: %lu\n", probe->name, GetLastError());
        CloseHandle(stderr_read);
        return 1;
    }

    DWORD wait_result = WaitForSingleObject(process.hProcess, 30000);
    if (wait_result != WAIT_OBJECT_0) {
        fprintf(stderr, "%s: child did not terminate normally (wait result %lu)\n", probe->name, wait_result);
        if (wait_result == WAIT_TIMEOUT) {
            TerminateProcess(process.hProcess, 111);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(stderr_read);
        return 1;
    }

    DWORD status;
    if (!GetExitCodeProcess(process.hProcess, &status)) {
        fprintf(stderr, "%s: GetExitCodeProcess failed: %lu\n", probe->name, GetLastError());
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(stderr_read);
        return 1;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    char diagnostic[512];
    DWORD total = 0;
    while (total < sizeof(diagnostic) - 1) {
        DWORD count;
        if (!ReadFile(stderr_read, diagnostic + total, (DWORD)(sizeof(diagnostic) - 1 - total), &count, NULL) ||
            count == 0) {
            break;
        }
        total += count;
    }
    diagnostic[total] = '\0';
    CloseHandle(stderr_read);

    if (!is_expected_status(status, probe->expected_status)) {
        fprintf(stderr, "%s: exit status 0x%08lx, expected 0x%08lx\n", probe->name, status,
                probe->expected_status);
        return 1;
    }
    if (strcmp(diagnostic, probe->expected_diagnostic) != 0) {
        fprintf(stderr, "%s: unexpected diagnostic: \"%s\"\n", probe->name, diagnostic);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    if (argc == 3 && strcmp(argv[1], "--probe") == 0) {
        const struct probe *probe = find_probe(argv[2]);
        return probe == NULL ? 112 : probe->function();
    }
    if (argc != 1) {
        return 113;
    }

    char module_path[MAX_PATH];
    DWORD path_length = GetModuleFileNameA(NULL, module_path, sizeof(module_path));
    if (path_length == 0 || path_length == sizeof(module_path)) {
        fprintf(stderr, "GetModuleFileName failed: %lu\n", GetLastError());
        return 1;
    }

    int failed = 0;
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        failed |= run_child(module_path, &probes[i]);
    }
    if (failed) {
        return 1;
    }
    printf("passed %zu Windows fault probes\n", sizeof(probes) / sizeof(probes[0]));
    return 0;
}
