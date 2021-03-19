#include "main.h"

static u_char *offsetptr(u_char *bytes, size_t offset)
{
    return bytes + offset;
}
static void ipv4_packet_process(struct prt_info *pi);

static void ipv6_packet_process(struct prt_info *pi);

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
    log_info("source     :\t%x:%x:%x:%x:%x:%x\n",
             /* MAC prefix begin */
             _ethhdr->h_source[0],
             _ethhdr->h_source[1],
             _ethhdr->h_source[2],
             /* MAC prefix end */
             _ethhdr->h_source[3],
             _ethhdr->h_source[4],
             _ethhdr->h_source[5]);
    log_info("destination:\t%x:%x:%x:%x:%x:%x\n",
             /* MAC prefix begin */
             _ethhdr->h_dest[0],
             _ethhdr->h_dest[1],
             _ethhdr->h_dest[2],
             /* MAC prefix end */
             _ethhdr->h_dest[3],
             _ethhdr->h_dest[4],
             _ethhdr->h_dest[5]);
    pi->ethhdr = _ethhdr;
    pi->ip_count++;
    // iphdr
    uint p = ntohs(_ethhdr->h_proto);
    if (p == ETH_P_IP)
    { // ipv4
        struct iphdr *_iphdr = (struct iphdr *)offsetptr((u_char *)_ethhdr, sizeof(struct ethhdr));
        pi->ipvnhdr = _iphdr;
    }
    else if (p == ETH_P_IPV6)
    { // ipv6
        struct ipv6hdr *_iphdr = (struct ipv6hdr *)offsetptr((u_char *)_ethhdr, sizeof(struct ipv6hdr));
        pi->ipvnhdr = _iphdr;
    }
    else
    {
        log_dbg("Unknow ethhdr.h_proto %d\n", p);
        return;
    }
    // try ipv4 first
    ipv4_packet_process(pi);
}

static void ipv4_packet_process(struct prt_info *pi)
{
    // if match ipv6, then turn to ipv6_packet_process.
    if (ntohs(pi->ethhdr->h_proto) == ETH_P_IPV6)
    {
        ipv6_packet_process(pi);
        return;
    }
    if (ntohs(pi->ethhdr->h_proto) != ETH_P_IP) // check again
        return;

    // ipv4
    pi->ipv4_count++;

    /*
     * 对于IP分片， 只处理第一个分片，
     * 当13位偏移量为0情况下，  一种是未分片，一种是第一个分片
     * 当13位偏移量非0， 一定是第二 or 第N分片
     */
    struct iphdr *_iphdr = (struct iphdr *)(pi->ipvnhdr);
    if ((ntohs(_iphdr->frag_off) & 0x1FFF) != 0)
        return;

    /* 探测， 应用协议类型 ,
     * detection_protocol_types 返回就是应用协议类型。 */
    int a = detection_protocol_types(pi);

    /* 函数， 返回应用协议类型标志。  */
    pi->app_pro_count[a]++;
    /* 统计协议类型， 并记录，  （包括， IP地址） */

    return;
}
// TODO
static void ipv6_packet_process(struct prt_info *pi)
{
    pi->ipv6_count++;
    return;
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
    struct iphdr *_iphdr = (struct iphdr *)(pi->ipvnhdr);
    /* protocol assert */
    switch (_iphdr->protocol)
    {
    case IPPROTO_TCP: /*  TCP  */
        pi->tcphdr = (struct tcphdr *)offsetptr((u_char *)_iphdr, (_iphdr->ihl * 4));
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
        break;
    case IPPROTO_UDP: /*  UDP  */
        pi->udphdr = (struct udphdr *)offsetptr((u_char *)_iphdr, (_iphdr->ihl * 4));
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
        /*  void  */
        break;
    }
    return ret;
}
