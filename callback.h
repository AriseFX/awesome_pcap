#ifndef __CALLBACK_H__
#define __CALLBACK_H__
#include "main.h"
#define DEFAULT_MEMORY_OOM_SIZE 1 << 20// 1 MB
/*
 * Display a mac address in readable format.
 * 0-2 max-prefix
 */
#define MAC_FMT "%x:%x:%x:%x:%x:%x\0"
#define MAC_SIZE sizeof(MAC_FMT)+1
#define MAC(addr)                                              \
    ((unsigned char *) &addr)[0],                              \
            ((unsigned char *) &addr)[1],                      \
            ((unsigned char *) &addr)[2],                      \
            ((unsigned char *) &addr)[3], /* MAC prefix end */ \
            ((unsigned char *) &addr)[4],                      \
            ((unsigned char *) &addr)[5]
/*
 * Display an IP address in readable format.
 */
#define NIPQUAD_FMT "%u.%u.%u.%u\0"
#define NIPQUAD_SIZE sizeof(NIPQUAD_FMT)+1
#define NIPQUAD(addr)                     \
    ((unsigned char *) &addr)[0],         \
            ((unsigned char *) &addr)[1], \
            ((unsigned char *) &addr)[2], \
            ((unsigned char *) &addr)[3]

extern void data_callback(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *bytes);
unsigned char *offsetptr(unsigned char *bytes, size_t offset);
#endif /* __CALLBACK_H__ */
