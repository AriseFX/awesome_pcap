#include <stdio.h>
#include "pmalloc.h"
#include "atomicvar.h"
#include "stdlib.h"

static size_t used_memory = 0;

static void pmalloc_oom(size_t size) {
    fprintf(stderr, "malloc: Out of memory trying to allocate %zu bytes\n",
            size);
    fflush(stderr);
    abort();
}
size_t pmalloc_used_memory(void) {
    size_t um;
    atomicGet(used_memory, um);
    return um;
}
void *p_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr)
        pmalloc_oom(size);
    size = pmalloc_size(ptr);
    atomicIncr(used_memory, size);
    return ptr;
}

void *p_calloc(size_t nmemb, size_t size) {
    void *ptr = calloc(nmemb, size);
    if (!ptr)
        pmalloc_oom(size);
    size = pmalloc_size(ptr);
    atomicIncr(used_memory, size);
    return ptr;
}
void p_free(void *ptr) {
    if (ptr == NULL)
        return;
    int size = pmalloc_size(ptr);
    atomicDecr(used_memory, size);
    free(ptr);
}