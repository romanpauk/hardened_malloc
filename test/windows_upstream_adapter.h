#ifndef WINDOWS_UPSTREAM_ADAPTER_H
#define WINDOWS_UPSTREAM_ADAPTER_H

// Keep the upstream test sources unchanged while directing their allocator calls to the
// standalone prefixed DLL. Include the CRT declarations before defining the mappings so
// the Windows CRT itself retains its ordinary allocation declarations.
#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>

#if defined(_MSC_VER)
#define __attribute__(x)
#endif

#ifdef __cplusplus
extern "C" {
#endif

void *h_malloc(size_t size);
void *h_calloc(size_t nmemb, size_t size);
void *h_realloc(void *ptr, size_t size);
void h_free(void *ptr);
int h_posix_memalign(void **memptr, size_t alignment, size_t size);
size_t h_malloc_usable_size(void *ptr);
void h_free_sized(void *ptr, size_t expected_size);
void h_free_aligned_sized(void *ptr, size_t alignment, size_t expected_size);

#ifdef __cplusplus
}
#endif

#define malloc(size) h_malloc(size)
#define calloc(nmemb, size) h_calloc(nmemb, size)
#define realloc(ptr, size) h_realloc(ptr, size)
#define free(ptr) h_free(ptr)
#define posix_memalign(memptr, alignment, size) h_posix_memalign(memptr, alignment, size)
#define malloc_usable_size(ptr) h_malloc_usable_size(ptr)
#define malloc_object_size(ptr) h_malloc_object_size(ptr)
#define free_sized(ptr, size) h_free_sized(ptr, size)
#define free_aligned_sized(ptr, alignment, size) h_free_aligned_sized(ptr, alignment, size)

#endif
