#include "main.h"
#include "./deps/src/cJSON/cJSON.h"
/* ordered frame packet data (all) */
struct g_prt_info_data _data = {
        .head = NULL,
        .tail = NULL,
};
struct cJSON *g_print_node(struct prt_info *node) {
    if (!node) {
        return 0;
    }
    cJSON *cur = cJSON_CreateObject();

    /* is tcp */
    cJSON_AddBoolToObject(cur, "istcp", node->istcp);
    /* ethhdr */
    cJSON *_ethhdr = cJSON_CreateObject();
    unsigned char h_source[sizeof(MAC_FMT)];
    unsigned char h_dest[sizeof(MAC_FMT)];
    sprintf(h_source, MAC_FMT, MAC(node->ethhdr->h_source));
    sprintf(h_dest, MAC_FMT, MAC(node->ethhdr->h_dest));
    /* source mac address */
    cJSON_AddStringToObject(_ethhdr, "h_source", h_source);
    /* destination mac address */
    cJSON_AddStringToObject(_ethhdr, "h_dest", h_dest);
    /* ethernet protocol */
    cJSON_AddStringToObject(_ethhdr, "h_proto", ntohs(node->ethhdr->h_proto) == ETH_P_IP ? "ipv4" : "ipv6");
    cJSON_AddItemToObject(cur, "ethhdr", _ethhdr);
    /* ipvn packet */
    cJSON *_ipvnhdr = cJSON_CreateObject();
    void *__ipvnhdr = node->ipvnhdr;
    unsigned char saddr[sizeof(NIPQUAD_FMT)];
    unsigned char daddr[sizeof(NIPQUAD_FMT)];
    switch (ntohs(node->ethhdr->h_proto)) {
        case ETH_P_IP:// ipv4
            /* source ip address */
            sprintf(saddr, NIPQUAD_FMT, NIPQUAD(((struct iphdr *) (node->ipvnhdr))->saddr));
            cJSON_AddStringToObject(_ipvnhdr, "saddr", saddr);
            /* destination ip address */
            sprintf(daddr, NIPQUAD_FMT, NIPQUAD(((struct iphdr *) (node->ipvnhdr))->daddr));
            cJSON_AddStringToObject(_ipvnhdr, "daddr", daddr);

        case ETH_P_IPV6:// ipv6
        default:
            break;
    }
    cJSON_AddItemToObject(cur, "ipvnhdr", _ipvnhdr);
    if (node->istcp) {
        /* source port */
        cJSON_AddNumberToObject(_ipvnhdr, "source_port", ntohs(((struct tcphdr *) (node->tcp_udp_hdr))->source));
        /* destination port */
        cJSON_AddNumberToObject(_ipvnhdr, "destination_port", ntohs(((struct tcphdr *) (node->tcp_udp_hdr))->dest));
        /* ack_seq seq syn ack fin rst */
        cJSON_AddNumberToObject(cur, "ack_seq", ntohl(((struct tcphdr *) (node->tcp_udp_hdr))->ack_seq));
        cJSON_AddNumberToObject(cur, "seq", ntohl(((struct tcphdr *) (node->tcp_udp_hdr))->seq));
        cJSON_AddNumberToObject(cur, "doff", ntohl(((struct tcphdr *) (node->tcp_udp_hdr))->doff));
        cJSON_AddBoolToObject(cur, "ack", ((struct tcphdr *) (node->tcp_udp_hdr))->ack);
        cJSON_AddBoolToObject(cur, "syn", ((struct tcphdr *) (node->tcp_udp_hdr))->syn);
        cJSON_AddBoolToObject(cur, "fin", ((struct tcphdr *) (node->tcp_udp_hdr))->fin);
        cJSON_AddBoolToObject(cur, "rst", ((struct tcphdr *) (node->tcp_udp_hdr))->rst);
        cJSON_AddBoolToObject(cur, "psh", ((struct tcphdr *) (node->tcp_udp_hdr))->psh);
        cJSON_AddBoolToObject(cur, "urg", ((struct tcphdr *) (node->tcp_udp_hdr))->urg);
        cJSON_AddBoolToObject(cur, "ece", ((struct tcphdr *) (node->tcp_udp_hdr))->ece);
        cJSON_AddBoolToObject(cur, "cwr", ((struct tcphdr *) (node->tcp_udp_hdr))->cwr);
    } else {
        /* source port */
        cJSON_AddNumberToObject(_ipvnhdr, "source_port", ntohs(((struct udphdr *) (node->tcp_udp_hdr))->source));
        /* destination port */
        cJSON_AddNumberToObject(_ipvnhdr, "destination_port", ntohs(((struct udphdr *) (node->tcp_udp_hdr))->dest));
    }
    return cur;
}
void g_print() {
    cJSON *g;
    g = cJSON_CreateObject();
    cJSON_AddNumberToObject(g, "pkt_count", _data.pkt_count);
    cJSON_AddNumberToObject(g, "ip_count", _data.ip_count);
    cJSON_AddNumberToObject(g, "ipv4_count", _data.ipv4_count);
    cJSON_AddNumberToObject(g, "ipv6_count", _data.ipv6_count);
    cJSON *g_arr = cJSON_AddArrayToObject(g, "data");
    struct prt_info *node = _data.head;
    for (/* void */; /* void */; /* void */) {
        if (!node) {
            break;
        }
        cJSON *cur = g_print_node(node);
        if (node->next_frame) {
            cJSON *cur_next = g_print_node(node->next_frame);
            cJSON_AddItemToObject(cur, "next", cur_next);
        }
        cJSON_AddItemToArray(g_arr, cur);
        node = node->next;
    }
    log_info("\n\n");
    log_info("%s\n", cJSON_PrintUnformatted(g));
    // log_info("%s\n", cJSON_Print(g));
    cJSON_Delete(g);
}
/*
* @argv[0] file to parse
*/
int main(int argc, char *argv[]) {
    /* sig_handle func init */
    sig_init();
    /* tcp group map init */
    _frame_map = dictCreate(10);
    int ret = EXIT_SUCCESS;
    if (argc < 2) {
        log_err("Please input : %s <pcap file name>\n", argv[0]);
        return 1;
    }
    /*  log_init() */
    log_dbg("Open pcap %s\n", argv[1]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(argv[1], errbuf);

    if (p == NULL) {
        log_err("Error for pcap_open_offline :%s\n", errbuf);
        ret = EXIT_FAILURE;
        goto clean;
    }
    pcap_loop(p, -1, data_callback, NULL);
    prt_info_out();
    pcap_close(p);
    g_print();
clean:
    fflush(stdout);
    fflush(stderr);
exit:
    return ret;
}
