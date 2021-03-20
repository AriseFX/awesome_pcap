#include "main.h"

/*
 * Display a mac address in readable format.
 * 0-2 max-prefix
 */
#define MAC_FMT "%x:%x:%x:%x:%x:%x"
#define MAC(addr)                                         \
    ((unsigned char *)&addr)[0],                          \
        ((unsigned char *)&addr)[1],                      \
        ((unsigned char *)&addr)[2],                      \
        ((unsigned char *)&addr)[3], /* MAC prefix end */ \
        ((unsigned char *)&addr)[4],                      \
        ((unsigned char *)&addr)[5]
/*
 * Display an IP address in readable format.
 */
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr)                \
    ((unsigned char *)&addr)[0],     \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

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
    // Ethernet packet
    struct ethhdr *_ethhdr = (struct ethhdr *)bytes;
    log_info("source mac     \t\t" MAC_FMT "\n", MAC(_ethhdr->h_source));
    log_info("destination mac\t\t" MAC_FMT "\n", MAC(_ethhdr->h_dest));
    pi->ethhdr = _ethhdr;
    pi->ip_count++;
    // Internet Protocol
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

    log_info("source ip     \t\t" NIPQUAD_FMT "\n", NIPQUAD(_iphdr->saddr));
    log_info("destination ip\t\t" NIPQUAD_FMT "\n", NIPQUAD(_iphdr->daddr));
    log_info("iphdr checksum16\t0x%x\n", ntohs(_iphdr->check));
    /* Transmission Control Protocol detection */
    int a = detection_protocol_types(pi);

    pi->app_pro_count[a]++;

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
        pi->istcp = 1;
        pi->tcp_udp_hdr = (struct tcphdr *)offsetptr((u_char *)_iphdr, (_iphdr->ihl * 4));
        struct tcphdr *_tcphdr = (struct tcphdr *)(pi->tcp_udp_hdr);
        log_info("source port     \t%d\n", ntohs(_tcphdr->source));
        log_info("destination port\t%u\n", ntohs(_tcphdr->dest));
        log_info("ack_seq \t\t\t%u\n", ntohl(_tcphdr->ack_seq));
        log_info("seq \t\t\t%u\n", ntohl(_tcphdr->seq));
        log_info("syn \t\t\t%u\n", (_tcphdr->syn));
        log_info("ack \t\t\t%u\n", (_tcphdr->ack));
        log_info("fin \t\t\t%u\n", (_tcphdr->fin));
        log_info("rst \t\t\t%u\n", (_tcphdr->rst));
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
        pi->istcp = 0;
        pi->tcp_udp_hdr = (struct udphdr *)offsetptr((u_char *)_iphdr, (_iphdr->ihl * 4));
        struct udphdr *_udphdr = (struct udphdr *)(pi->tcp_udp_hdr);
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
