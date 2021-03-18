#include "main.h"

static u_char *offsetptr(u_char *bytes, size_t offset)
{
    return bytes + offset;
}
static int ip_packet_process(struct prt_info *pi);

static int ipv6_packet_process(struct prt_info *pi);

static int detection_protocol_types(struct prt_info *pi);

void data_callback(u_char *user, const struct pcap_pkthdr *h,
                   const u_char *bytes)
{
    prt_info_t *pi = (prt_info_t *)user;

    pi->pkt_count++;
    pi->pkthdr = (struct pcap_pkthdr *)h;
    // only handle effective packet
    if (h->caplen != h->len)
        return;
    // ethhdr
    struct ethhdr *_ethhdr = (struct ethhdr *)bytes;
    pi->ethhdr = _ethhdr;
    if (ntohs(pi->ethhdr->h_proto) != ETH_P_IP)
        return;
    pi->ip_count++;
    // iphdr
    struct iphdr *_iphdr = (struct iphdr *)offsetptr((u_char *)_ethhdr, sizeof(struct ethhdr));
    pi->iphdr = _iphdr;

    ip_packet_process(pi);
}

static int ip_packet_process(struct prt_info *pi)
{
    // ipv6
    if (pi->iphdr->version == 6)
    {
        ipv6_packet_process(pi);
        return 0;
    }
    if (pi->iphdr->version != 4)
        return 0;

    // ipv4
    pi->ipv4_count++;

    /*
     * 对于IP分片， 只处理第一个分片，
     * 当13位偏移量为0情况下，  一种是未分片，一种是第一个分片
     * 当13位偏移量非0， 一定是第二 or 第N分片
     */
    if ((ntohs(pi->iphdr->frag_off) & 0x1FFF) != 0)
        return 0;

    /* 探测， 应用协议类型 ,
     * detection_protocol_types 返回就是应用协议类型。 */
    int a = detection_protocol_types(pi);

    /* 函数， 返回应用协议类型标志。  */
    pi->app_pro_count[a]++;
    /* 统计协议类型， 并记录，  （包括， IP地址） */

    return 0;
}

static int ipv6_packet_process(struct prt_info *pi)
{
    return 0;
}

/**
 * 完成对应用协议的探测， 返回应用协议标示， 
 *  返回 0， 表示未知类型协议
 *  返回1， 代表ssh协议
 *  返回2， 代表tftp协议
 *  。。。。 协议类型在protocol.h 中定义
 */
static int detection_protocol_types(struct prt_info *pi)
{
    int ret = PRO_UNKNOWN;
    int i;

    /* 区分upd 和 tcp协议，  */
    switch (pi->iphdr->protocol)
    {

    case IPPROTO_TCP: /*  TCP 协议 */
        pi->tcphdr = (struct tcphdr *)offsetptr((u_char *)pi->iphdr, (pi->iphdr->ihl * 4));

        for (i = 0; i < PRO_TYPES_MAX; i++)
        {

            if (pi->pro_detec[i].flag == FLAG_TCP)
            {
                if ((pi->pro_detec[i].pro_detec != NULL) && pi->pro_detec[i].pro_detec(pi) != 0)
                {
                    ret = i; /*  i指代某种协议类型 */
                    break;
                }
            }
        }

    case IPPROTO_UDP: /*  UDP协议 */
        pi->udphdr = (struct udphdr *)offsetptr((u_char *)pi->iphdr, (pi->iphdr->ihl * 4));

        for (i = 0; i < PRO_TYPES_MAX; i++)
        {

            if (pi->pro_detec[i].flag == FLAG_UDP)
            {
                if ((pi->pro_detec[i].pro_detec != NULL) && pi->pro_detec[i].pro_detec(pi) != 0)
                {
                    ret = i; /*  i指代某种协议类型 */
                    break;
                }
            }
        }

        break;

    default:
        break;
        /* Nothing to do */
    }

    /*  应用协议 */

    return ret;
}
