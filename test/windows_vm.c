#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <stddef.h>
#include <string.h>

#include "memory.h"
#include "win.h"

static int query_state(void *address, DWORD state, DWORD protection) {
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(address, &info, sizeof(info)) != sizeof(info)) {
        return 1;
    }
    if (info.State != state) {
        return 2;
    }
    if (state != MEM_FREE && info.Protect != protection) {
        return 3;
    }
    return 0;
}

int main(void) {
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size != 4096) {
        return 10;
    }

    size_t reservation_size = page_size * 4;
    unsigned char *reservation = memory_map(reservation_size);
    if (reservation == NULL) {
        return 11;
    }
    if (query_state(reservation, MEM_RESERVE, 0)) {
        return 12;
    }

    unsigned char *span = reservation + page_size;
    size_t span_size = page_size * 2;
    if (memory_protect_rw(span, span_size)) {
        return 13;
    }
    if (query_state(span, MEM_COMMIT, PAGE_READWRITE)) {
        return 14;
    }
    memset(span, 0xa5, span_size);

    if (memory_protect_ro(span, span_size)) {
        return 15;
    }
    if (query_state(span, MEM_COMMIT, PAGE_READONLY)) {
        return 16;
    }
    if (memory_protect_rw(span, span_size)) {
        return 17;
    }

    if (memory_purge(span, span_size)) {
        return 18;
    }
    for (size_t i = 0; i < span_size; i++) {
        if (span[i] != 0) {
            return 19;
        }
    }

    memset(span, 0x5a, span_size);
    if (memory_map_fixed(span, span_size)) {
        return 20;
    }
    if (query_state(span, MEM_RESERVE, 0)) {
        return 21;
    }
    if (memory_protect_rw(span, span_size)) {
        return 22;
    }
    for (size_t i = 0; i < span_size; i++) {
        if (span[i] != 0) {
            return 23;
        }
    }

    // The common page helper can pass an interior guarded range for an over-aligned allocation.
    // The Windows backend must recover and release the containing reservation.
    if (memory_unmap(span, span_size)) {
        return 24;
    }
    if (query_state(reservation, MEM_FREE, 0)) {
        return 25;
    }
    return 0;
}
