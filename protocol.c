/* 协议保存和比对 */
#include "protocol.h"
#include "main.h"

/* 完成对已识别应用协议的四元组保存 */

struct four_tuples {
    u32_t sip;   /* 源IP */
    u32_t dip;   /* 目的IP */
    u16_t sport; /* 源端口 */
    u16_t dport; /* 目的端口 */
};

static struct four_tuples four[PRO_TYPES_MAX] = {0};

/* 保存四元组 */
int pro_types_save(struct prt_info *pi, int types) {
    /* 记录源IP， 目的IP */
    // four[types].sip = pi->iphdr->saddr;
    // four[types].dip = pi->iphdr->daddr;

    // /* 记录TCP 源端口， 目的端口 */
    // if (pi->tcphdr != NULL)
    // {
    //     four[types].sport = pi->tcphdr->source;
    //     four[types].dport = pi->tcphdr->dest;
    // }

    // /* 保存UDP源端口，和 目的端口 */
    // if (pi->udphdr != NULL)
    // {
    //     four[types].sport = pi->udphdr->source;
    //     four[types].dport = pi->udphdr->dest;
    // }

    return 0;
}

/**
 * 对与当前数据包， 和已知类型应用协议四元组，作对比，
 *  如果为已知类型， 返回1，
 *  如果不匹配已知类型， 返回0；
 */
int pro_types_cmp(struct prt_info *pi, int types) {
    /* tcp 协议的比对 */

    // if (pi->tcphdr != NULL) {
    //     /**
    //      *  XXX:
    //      *  假设已保存  A  ---> B发送数据包的四元组
    //      *
    //      *  如果此次是    A ---- > B
    //      *  sip == sipA  && dip==dipB && sport == sportA  && dport == dportB
    //      *
    //      *  如果此次数据  B---> A
    //      *  sip ==sipB && dip==dipA   && sport==sportB && dport == dportA
    //      */

    //     /* A---> B */
    //     if (four[types].sip == pi->iphdr->saddr
    //         && four[types].dip == pi->iphdr->daddr
    //         && four[types].sport == pi->tcphdr->source
    //         && four[types].dport == pi->tcphdr->dest)
    //         return 1;

    //     /* B ---> A */
    //     if (four[types].sip == pi->iphdr->daddr
    //         && four[types].dip == pi->iphdr->saddr
    //         && four[types].sport == pi->tcphdr->dest
    //         && four[types].dport == pi->tcphdr->source)

    //         return 1;

    // } else if (pi->udphdr != NULL) {

    //     /* A---> B */
    //     if (four[types].sip == pi->iphdr->saddr
    //         && four[types].dip == pi->iphdr->daddr
    //         && ((four[types].sport == pi->udphdr->source) || (four[types].dport == pi->udphdr->dest))
    //             )
    //         return 1;

    //     /* B ---> A */
    //     if (four[types].sip == pi->iphdr->daddr
    //         && four[types].dip == pi->iphdr->saddr
    //         && ((four[types].sport == pi->udphdr->dest)
    //             || (four[types].dport == pi->udphdr->source)))

    //         return 1;

    //     /* udp协议的比对 */
    //     /* TODO:  需要补充udp协议比对代码 */
    // } else {
    //     /* Nothing to do  */
    //     ;
    // }

    return 0;
}
