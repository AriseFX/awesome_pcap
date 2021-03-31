#ifndef __PMALLOC_H__
#define __PMALLOC_H__
#ifdef __GLIBC__
// #include <malloc.h>
#endif
#ifdef __APPLE__
#include <malloc/malloc.h>
#define pmalloc_size(p) malloc_size(p)
#endif
#ifdef __GLIBC__
#include <malloc.h>
#define pmalloc_size(p) malloc_usable_size(p)
#endif
size_t pmalloc_used_memory(void);
void *p_malloc(size_t size);
void *p_calloc(size_t nmemb, size_t size);
void p_free(void *ptr);

#endif /* __PMALLOC_H__ */