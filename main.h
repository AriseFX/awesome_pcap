#ifndef __MAIN_H__
#define __MAIN_H__
/* void warning macro */
#define UNUSED(V) ((void) V)
#define STDOUT_FD 2
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <arpa/inet.h>

#ifdef __linux__
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#endif

#ifdef __APPLE__
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#define ethhdr ether_header
#define h_proto ether_type
#define ETH_P_IP ETHERTYPE_IP
#define ETH_P_IPV6 ETHERTYPE_IPV6
#define h_source ether_shost
#define h_dest ether_dhost
#define iphdr ip
#define ipv6hdr ip6_hdr
#define frag_off ip_off
#endif

#include <netinet/in.h>


#include "./deps/src/rax/rax.h"
#include <pcap/pcap.h>

#include "atomicvar.h"
#include "log.h"
#include "protocol_info.h"

#include "callback.h"

#include "protocol.h"

#include "debug.h"

#ifdef PRO_TYPES_SSH

#include "http.h"
#include "ssh.h"

#endif /* PRO_TYPES_SSH */
#include "four_tuple_map.h"
struct g_prt_info_data {
    u32_t pkt_count;  /*  用于统计文件中， 所有patcket的数量 */
    u32_t ip_count;   /* IP 报文的数量， */
    u32_t ipv4_count; /* IPV4报文的数量 */
    u32_t ipv6_count; /* IPV6报文的数量 */
    struct prt_info *head;
    struct prt_info *tail;
};

struct g_prt_info_data _data;

struct q_map *_frame_map;
/* protocol radix tree */
rax *_rax;
#endif /* __MAIN_H__ */
