#ifndef __ATOMIC_VAR_H__
#define __ATOMIC_VAR_H__

#define atomicIncr(var, count) __atomic_add_fetch(&var, (count), __ATOMIC_RELAXED)
#define atomicDecr(var, count) __atomic_sub_fetch(&var, (count), __ATOMIC_RELAXED)
#define atomicGet(var, dstvar)                            \
    do {                                                  \
        dstvar = __atomic_load_n(&var, __ATOMIC_RELAXED); \
    } while (0)
#endif /* __ATOMIC_VAR_H__ */