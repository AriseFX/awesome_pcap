#include "pmalloc.h"
#include "stdlib.h"
#include "atomicvar.h"

static size_t used_memory = 0;

static void pmalloc_oom(size_t size)
{
  fprintf(stderr, "malloc: Out of memory trying to allocate %zu bytes\n",
          size);
  fflush(stderr);
  abort();
}

void *p_malloc(size_t size)
{
  void *ptr = malloc(size);
  if (!ptr)
    pmalloc_oom(size);
  size = pmalloc_size(ptr);
  atomicIncr(used_memory, size);
  return ptr;
}
void p_free(void *ptr)
{
  if (ptr == NULL)
    return;
  int size = pmalloc_size(ptr);
  atomicDecr(used_memory, size);
  free(ptr);
}