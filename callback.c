#include "callback.h"
#include "pmalloc.h"

static uint id_global = 0;
unsigned char *offsetptr(unsigned char *bytes, size_t offset) {
    return bytes + offset;
}
static int ipv4_packet_process(struct prt_info *pi);

static int ipv6_packet_process(struct prt_info *pi);

static int detection_protocol_types(struct prt_info *pi);

void data_callback(unsigned char *user, const struct pcap_pkthdr *h,
                   const unsigned char *bytes) {
    id_global++;
    size_t mem = pmalloc_used_memory();
    pcap_t *t = (pcap_t *) user;
    if (mem >= DEFAULT_MEMORY_OOM_SIZE) {// OOM
        log_err("pcap out of memory to continue doing job, please check out your config.\n");
        pcap_breakloop(t);
    }
    _data.pkt_count++;
    prt_info_t *pi = new_prt_info();
    pi->id = id_global;
    if (pi == NULL) {
        log_err("initial protocol info failed\n");
        return;
    }
    pi->pkthdr = (struct pcap_pkthdr *) h;
    // only handle effective packet
    if (h->caplen != h->len)
        return;
    // Ethernet packet
    struct ethhdr *_ethhdr = (struct ethhdr *) bytes;
    log_dbg("%x\n", _ethhdr);
    log_dbg("source mac     \t\t" MAC_FMT "\n", MAC(_ethhdr->h_source));
    log_dbg("destination mac\t\t" MAC_FMT "\n", MAC(_ethhdr->h_dest));
    pi->ethhdr = _ethhdr;
    // Internet Protocol
    unsigned int p = ntohs(_ethhdr->h_proto);
    if (p == ETH_P_IP) {// ipv4
        struct iphdr *_iphdr = (struct iphdr *) offsetptr((unsigned char *) _ethhdr, sizeof(struct ethhdr));
        pi->ipvnhdr = _iphdr;
    } else if (p == ETH_P_IPV6) {// ipv6
        struct ipv6hdr *_iphdr = (struct ipv6hdr *) offsetptr((unsigned char *) _ethhdr, sizeof(struct ipv6hdr));
        pi->ipvnhdr = _iphdr;
    } else {
        log_dbg("Unknow ethhdr.h_proto %d\n", p);
        return;
    }
    // try ipv4 first
    int protocol = ipv4_packet_process(pi);
    if (protocol == PRO_UNKNOWN) {
        return;
    }
    ptr_save(pi);// TODO store to global data to render in html
    // prt_info_free(pi);
    if (!pi->protocol) { /* if not set, basic tcp or udp protocol should be set */
        pi->protocol = pi->istcp ? "TCP" : "UDP";
    }
    dict_add(_frame_map, pi);
    return;
}

static int ipv4_packet_process(struct prt_info *pi) {
    // if match ipv6, then turn to ipv6_packet_process.
    if (ntohs(pi->ethhdr->h_proto) == ETH_P_IPV6) {
        return ipv6_packet_process(pi);
    }
    if (ntohs(pi->ethhdr->h_proto) != ETH_P_IP)// check again
        return PRO_UNKNOWN;

    /*
     * ??????IP????????? ???????????????????????????
     * ???13???????????????0????????????  ?????????????????????????????????????????????
     * ???13???????????????0??? ??????????????? or ???N??????
     */
    struct iphdr *_iphdr = (struct iphdr *) (pi->ipvnhdr);
    if ((ntohs(_iphdr->frag_off) & 0x1FFF) != 0)
        return PRO_UNKNOWN;
#ifdef __linux__
    log_dbg("source ip     \t\t" NIPQUAD_FMT "\n", NIPQUAD(_iphdr->saddr));
    log_dbg("destination ip\t\t" NIPQUAD_FMT "\n", NIPQUAD(_iphdr->daddr));
    log_dbg("iphdr checksum16\t0x%x\n", ntohs(_iphdr->check));
#elif defined(__APPLE__)
#endif
    /* Transmission Control Protocol detection */
    int a = detection_protocol_types(pi);

    pi->app_pro_count[a]++;

    return a;
}
// TODO
static int ipv6_packet_process(struct prt_info *pi) {
    return PRO_UNKNOWN;
}

/**
 * ????????????????????????????????? ??????????????????????????? 
 *  ?????? 0??? ????????????????????????
 *  ??????1??? ??????ssh??????
 *  ??????2??? ??????tftp??????
 *  ???????????? ???????????????protocol.h ?????????
 */
static int detection_protocol_types(struct prt_info *pi) {
    int ret = PRO_UNKNOWN;
    int i;
    struct iphdr *_iphdr = (struct iphdr *) (pi->ipvnhdr);
    /* protocol assert */
    switch (
#ifdef __linux__
            _iphdr->protocol
#elif defined(__APPLE__)
            _iphdr->ip_p
#endif
    ) {
        case IPPROTO_TCP: /*  TCP  */
            ret = IPPROTO_TCP;
            pi->istcp = 1;
            pi->tcp_udp_hdr = (struct tcphdr *) offsetptr((unsigned char *) _iphdr,
#ifdef __linux__
                                                          (_iphdr->ihl * 4));
            log_dbg("source port     \t%d\n", ntohs(_tcphdr->source));
            log_dbg("destination port\t%u\n", ntohs(_tcphdr->dest));
            log_dbg("ack_seq \t\t\t%u\n", ntohl(_tcphdr->ack_seq));
            log_dbg("seq \t\t\t%u\n", ntohl(_tcphdr->seq));
            log_dbg("syn \t\t\t%u\n", (_tcphdr->syn));
            // _tcphdr->th_flags
            log_dbg("ack \t\t\t%u\n", (_tcphdr->ack));
            log_dbg("fin \t\t\t%u\n", (_tcphdr->fin));
            log_dbg("rst \t\t\t%u\n", (_tcphdr->rst));
#elif __APPLE__
                                                          (_iphdr->ip_hl * 4));
#endif
            struct tcphdr *_tcphdr = (struct tcphdr *) (pi->tcp_udp_hdr);
#ifdef __linux__
            pi->len = ntohs(_iphdr->tot_len) - _iphdr->ihl * 4 - _tcphdr->doff * 4;
            pi->data = offsetptr((unsigned char *) _tcphdr, _tcphdr->doff * 4);
#elif defined(__APPLE__)
            pi->len = ntohs(_iphdr->ip_len) - _iphdr->ip_hl * 4 - _tcphdr->th_off * 4;
            pi->data = offsetptr((unsigned char *) _tcphdr, _tcphdr->th_off * 4);
#endif
            break;
        case IPPROTO_UDP: /*  UDP  */
            ret = IPPROTO_UDP;
            pi->istcp = 0;
            pi->tcp_udp_hdr = (struct udphdr *) offsetptr((unsigned char *) _iphdr,
#ifdef __linux__
                                                          (_iphdr->ihl * 4)
#elif defined(__APPLE__)
                                                          (_iphdr->ip_hl * 4)
#endif
            );
            struct udphdr *_udphdr = (struct udphdr *) (pi->tcp_udp_hdr);
            for (i = 0; i < PRO_TYPES_MAX; i++) {
                if (pi->pro_detec[i].flag == FLAG_UDP) {
                    if ((pi->pro_detec[i].pro_detec != NULL) && pi->pro_detec[i].pro_detec(pi) != 0) {
                        ret = i; /*  i???????????????????????? */
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
