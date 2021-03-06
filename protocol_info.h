#ifndef __PROTOCOL_INFO__
#define __PROTOCOL_INFO__

#include "protocol.h"

#include "main.h"

/**
 *  文件用于，对协议信息的定义，和初始化
 * 
 */

/* 基础类型定义 */
typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

/*  应用协议探测引擎，函数指针 */

struct prt_info;

typedef int (*detec_pro_t)(struct prt_info *pi);

#define FLAG_TCP 0
#define FLAG_UDP 1

struct pro_detec_info {
    int flag;              /* 0, TCP,  1, UDP, ... */
    detec_pro_t pro_detec; /*  应用协议探测引擎 */
};
/*  定义一个结构体， 用于记录和输出结果相关的一些信息 */
typedef struct prt_info {
    uint id;
    size_t len;
    /* .... 视需添加。。。 */

    /* 用来统计应用协议个数, 该值为零， 协议没有 */
    u32_t app_pro_count[PRO_TYPES_MAX];

    /* 函数指针数组，记录协议（ssh\tftp）探测引擎 */
    struct pro_detec_info pro_detec[PRO_TYPES_MAX];

    /* 用于记录当前packet中个成员的地址，
     * packet header， eth_header, ip_header, tcp_header or udp_header, data*/
    struct pcap_pkthdr *pkthdr;
    struct ethhdr *ethhdr;
    // ethpacket header maybe ipv4 or ipv6
    void *ipvnhdr;
    u8_t istcp;// 1 tcp 0 udp
    void *tcp_udp_hdr;
    u8_t saved;                 // whether do ptr_save
    struct prt_info *next;      // capture order next ptr
    struct prt_info *next_frame;// next frame -- group by four tuple info
    struct prt_info *dup;       // duplicate list ptr
    uint dup_count;
    void *data;                 // data prt
    char *protocol;             // protocol name (Front end display)
    char *print_message;        // custom information (Front end display)
} prt_info_t;

/*  初始化，协议信息函数 */
extern prt_info_t *new_prt_info(void);

/* 释放协议信息 */
void prt_info_free(prt_info_t *);
void *ptr_save(prt_info_t *);
/*  协议信息输出 */

extern int prt_info_out();

#endif /* __PROTOCOL_INFO__  */
