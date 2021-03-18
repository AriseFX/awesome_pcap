
#ifndef __PMALLOC_H__
#define __PMALLOC_H__

#include <malloc.h>

#define pmalloc_size(p) malloc_usable_size(p)

void *p_malloc(size_t size);
void *p_calloc(size_t nmemb, size_t size);
void p_free(void *ptr);

#endif /* __PMALLOC_H__ */