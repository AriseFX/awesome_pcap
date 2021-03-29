/**
 * 完成对协议信息的初始化， 和相关操作
 * 
 */
#include "main.h"
#include "pmalloc.h"
static char *pro_string[PRO_TYPES_MAX] = {
        PRO_STRINGS};

/**
 * 对协议信息的初始化
 * @return 初始化失败，返回NULL
 *         成功，返回prt_info_t类型指针
 */
prt_info_t *new_prt_info(void) {
    prt_info_t *pi = p_calloc(1, sizeof(*pi));

    /* 初始化应用协议探测引擎 */

    /* ssh协议探测 */
#ifdef PRO_TYPES_SSH
    pi->pro_detec[PRO_TYPES_SSH].flag = FLAG_TCP;
    pi->pro_detec[PRO_TYPES_SSH].pro_detec = detec_ssh;
#endif /* PRO_TYPES_SSH */

#ifdef PRO_TYPES_HTTP
    pi->pro_detec[PRO_TYPES_HTTP].flag = FLAG_TCP;
    pi->pro_detec[PRO_TYPES_HTTP].pro_detec = detec_http;
#endif /* PRO_TYPES_SSH */
    /* ... 按需添加 */

    return pi;
}
/*
 * copy all the data that libpcap hold
 * do not copy the user-level data such as pi->protocol pi->print_message
 */
void *ptr_save(prt_info_t *pi) {
    if (pi->saved) {
        return pi;
    }
    struct pcap_pkthdr *_pkthdr = p_malloc(sizeof(struct pcap_pkthdr));
    memcpy(_pkthdr, pi->pkthdr, sizeof(struct pcap_pkthdr));
    pi->pkthdr = _pkthdr;

    struct ethhdr *_ethhdr = p_malloc(sizeof(struct ethhdr));
    memcpy(_ethhdr, pi->ethhdr, sizeof(struct ethhdr));
    pi->ethhdr = _ethhdr;
    /* ipv4 ipv6 copy */
    void *_ipvnhdr;
    switch (ntohs(pi->ethhdr->h_proto)) {
        case ETH_P_IP:
            _ipvnhdr = p_malloc(sizeof(struct iphdr));
            memcpy(_ipvnhdr, pi->ipvnhdr, sizeof(struct iphdr));
            break;
        case ETH_P_IPV6:
            _ipvnhdr = p_malloc(sizeof(struct ipv6hdr));
            memcpy(_ipvnhdr, pi->ipvnhdr, sizeof(struct ipv6hdr));
            break;
    }
    pi->ipvnhdr = _ipvnhdr;
    /* _tcp_udp_hdr copy */
    void *_tcp_udp_hdr;
    if (pi->istcp) {
        _tcp_udp_hdr = p_malloc(sizeof(struct tcphdr));
        memcpy(_tcp_udp_hdr, pi->tcp_udp_hdr, sizeof(struct tcphdr));
    } else {
        _tcp_udp_hdr = p_malloc(sizeof(struct udphdr));
        memcpy(_tcp_udp_hdr, pi->tcp_udp_hdr, sizeof(struct udphdr));
    }
    pi->tcp_udp_hdr = _tcp_udp_hdr;
    if (!pi->saved) {
        _data.ip_count++;
        switch (ntohs(pi->ethhdr->h_proto)) {
            case ETH_P_IPV6:
                _data.ipv6_count++;
            case ETH_P_IP:
                _data.ipv4_count++;
            default:
                break;
        }
        // store to _data
        if (!_data.tail) {
            _data.head = _data.tail = pi;
        } else {
            _data.tail->next = pi;
            _data.tail = pi;
        }
    }
    // finished
    if (pi->len > 0) {
        void *_data = p_malloc(pi->len);
        memcpy(_data, pi->data, pi->len);
        pi->data = _data;
    }
    pi->saved = 1;
    return pi;
}
/* 对协议信息的 释放 */
void prt_info_free(prt_info_t *pi) {
    if (pi->saved) {
        p_free(pi->pkthdr);
        p_free(pi->ethhdr);
        p_free(pi->ipvnhdr);
        p_free(pi->tcp_udp_hdr);
    }
    if (pi->protocol) {
        p_free(pi->protocol);
    }
    if (pi->print_message) {
        p_free(pi->print_message);
    }
    if (pi->data) {
        p_free(pi->data);
    }
    return p_free(pi);
}

/* 对协议信息 输出 */
int prt_info_out() {
    /*  统计报文数量 */
    log_dbg("\nPacket: \n\n");
    log_dbg("\t Packet count: %d\n ", _data.pkt_count);
    log_dbg("\t IP packet  count: %d\n ", _data.ip_count);
    log_dbg("\t IPV4 packet  count: %d\n ", _data.ipv4_count);

    // /* 输出已探测应用协议的包个数 */

    // log_info("\n\n Application Protocol : \n\n");
    // int i;
    // for (i = 1; i < PRO_TYPES_MAX; i++)
    // {
    //     if (pi->app_pro_count[i] != 0)
    //     {
    //         log_info("\t%s:%u\n", pro_string[i], pi->app_pro_count[i]);
    //     }
    // }

    // /* 输出未知类型的数据包数量 */
    // log_info("\t%s:%u\n", pro_string[0], pi->app_pro_count[0]);

    return 0;
}
