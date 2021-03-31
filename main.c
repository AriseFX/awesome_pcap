#include "main.h"
#include "./deps/src/cJSON/cJSON.h"
#include "./deps/src/rax/rax.c"
/* ordered frame packet data (all) */
struct g_prt_info_data _data = {
        .head = NULL,
        .tail = NULL,
};
static int fd, fd2;
/*
 * http protocol init
 */
static char *METHODS[] = {
        "CONNECT",
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PUT",
        "TRACE",
};
void init_pro_detec() {
    _rax = raxNew();
    int method_len = sizeof(METHODS) / sizeof(char *);
    for (int i = 0; i < method_len; i++) {
        raxInsert(_rax, (unsigned char *) METHODS[i], strlen(METHODS[i]), detec_http, NULL);
    }
}
struct cJSON *g_print_node(struct prt_info *node) {
    if (!node) {
        return 0;
    }
    cJSON *cur = cJSON_CreateObject();
    cJSON_AddNumberToObject(cur, "id", node->id);

    /* is tcp */
    cJSON_AddBoolToObject(cur, "istcp", node->istcp);
    /* ethhdr */
    cJSON *_ethhdr = cJSON_CreateObject();
    unsigned char h_source[sizeof(MAC_FMT)];
    unsigned char h_dest[sizeof(MAC_FMT)];
    sprintf((char *) h_source, MAC_FMT, MAC(node->ethhdr->h_source));
    sprintf((char *) h_dest, MAC_FMT, MAC(node->ethhdr->h_dest));
    /* source mac address */
    cJSON_AddStringToObject(_ethhdr, (const char *) "h_source", (const char *) h_source);
    /* destination mac address */
    cJSON_AddStringToObject(_ethhdr, (const char *) "h_dest", (const char *) h_dest);
    /* ethernet protocol */
    cJSON_AddStringToObject(_ethhdr, (const char *) "h_proto", (const char *) (ntohs(node->ethhdr->h_proto) == ETH_P_IP ? "ipv4" : "ipv6"));
    cJSON_AddItemToObject(cur, (const char *) "ethhdr", _ethhdr);
    /* ipvn packet */
    cJSON *_ipvnhdr = cJSON_CreateObject();
    void *__ipvnhdr = node->ipvnhdr;
    unsigned char saddr[sizeof(NIPQUAD_FMT)];
    unsigned char daddr[sizeof(NIPQUAD_FMT)];
    switch (ntohs(node->ethhdr->h_proto)) {
        case ETH_P_IP:// ipv4
#ifdef __linux__
            /* source ip address */
            sprintf((char *) saddr, NIPQUAD_FMT, NIPQUAD(((struct iphdr *) (node->ipvnhdr))->saddr));
            cJSON_AddStringToObject(_ipvnhdr, "saddr", saddr);
            /* destination ip address */
            sprintf((char *) daddr, NIPQUAD_FMT, NIPQUAD(((struct iphdr *) (node->ipvnhdr))->daddr));
            cJSON_AddStringToObject(_ipvnhdr, "daddr", daddr);
#elif defined(__APPLE__)
            /* source ip address */
            sprintf((char *) saddr, NIPQUAD_FMT, NIPQUAD(((struct iphdr *) (node->ipvnhdr))->ip_src));
            cJSON_AddStringToObject(_ipvnhdr, "saddr", (const char *) saddr);
            // /* destination ip address */
            sprintf((char *) daddr, NIPQUAD_FMT, NIPQUAD(((struct iphdr *) (node->ipvnhdr))->ip_dst));
            cJSON_AddStringToObject(_ipvnhdr, "daddr", (const char *) daddr);
#endif
        case ETH_P_IPV6:// ipv6
        default:
            break;
    }

    cJSON_AddNumberToObject(cur, "len", node->len);
    cJSON_AddItemToObject(cur, "ipvnhdr", _ipvnhdr);
    if (node->istcp) {
#ifdef __linux__
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
#elif defined(__APPLE__)
        /* source port */
        cJSON_AddNumberToObject(_ipvnhdr, "source_port", ntohs(((struct tcphdr *) (node->tcp_udp_hdr))->th_sport));
        /* destination port */
        cJSON_AddNumberToObject(_ipvnhdr, "destination_port", ntohs(((struct tcphdr *) (node->tcp_udp_hdr))->th_dport));
        /* ack_seq seq syn ack fin rst */
        cJSON_AddNumberToObject(cur, "ack_seq", ntohl(((struct tcphdr *) (node->tcp_udp_hdr))->th_ack));
        cJSON_AddNumberToObject(cur, "seq", ntohl(((struct tcphdr *) (node->tcp_udp_hdr))->th_seq));
        cJSON_AddNumberToObject(cur, "doff", ntohl(((struct tcphdr *) (node->tcp_udp_hdr))->th_off));
        cJSON_AddBoolToObject(cur, "ack", ((struct tcphdr *) (node->tcp_udp_hdr))->th_flags | TH_ACK);
        cJSON_AddBoolToObject(cur, "syn", ((struct tcphdr *) (node->tcp_udp_hdr))->th_flags | TH_SYN);
        cJSON_AddBoolToObject(cur, "fin", ((struct tcphdr *) (node->tcp_udp_hdr))->th_flags | TH_FIN);
        cJSON_AddBoolToObject(cur, "rst", ((struct tcphdr *) (node->tcp_udp_hdr))->th_flags | TH_RST);
        cJSON_AddBoolToObject(cur, "psh", ((struct tcphdr *) (node->tcp_udp_hdr))->th_flags | TH_PUSH);
        cJSON_AddBoolToObject(cur, "urg", ((struct tcphdr *) (node->tcp_udp_hdr))->th_flags | TH_URG);
        cJSON_AddBoolToObject(cur, "ece", ((struct tcphdr *) (node->tcp_udp_hdr))->th_flags | TH_ECE);
        cJSON_AddBoolToObject(cur, "cwr", ((struct tcphdr *) (node->tcp_udp_hdr))->th_flags | TH_CWR);
#endif
    } else {
#ifdef __linux__
        /* source port */
        cJSON_AddNumberToObject(_ipvnhdr, "source_port", ntohs(((struct udphdr *) (node->tcp_udp_hdr))->source));
        /* destination port */
        cJSON_AddNumberToObject(_ipvnhdr, "destination_port", ntohs(((struct udphdr *) (node->tcp_udp_hdr))->dest));
#endif
        /* source port */
        cJSON_AddNumberToObject(_ipvnhdr, "source_port", ntohs(((struct udphdr *) (node->tcp_udp_hdr))->uh_sport));
        /* destination port */
        cJSON_AddNumberToObject(_ipvnhdr, "destination_port", ntohs(((struct udphdr *) (node->tcp_udp_hdr))->uh_dport));
    }
    /* print user-lever data */
    if (node->protocol) {
        cJSON_AddStringToObject(cur, "protocol", node->protocol);
        cJSON_AddStringToObject(cur, "print_message", node->print_message);
    }
    if (node->dup) {
        cJSON *dup_array = cJSON_CreateArray();
        struct prt_info *loop = node->dup;
        for (/* void */; /* void */; /* void */) {
            cJSON *dup_node = g_print_node(loop);
            cJSON_AddItemToArray(dup_array, dup_node);
            if (loop->dup) {
                loop = loop->dup;
            } else {
                break;
            }
        }
        cJSON_AddItemToObject(cur, "dup", dup_array);
    }
    cJSON_AddNumberToObject(cur, "dup_count", node->dup_count);
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
        if (node->dup) {
            cJSON *dup_array = cJSON_CreateArray();
            struct prt_info *loop = node->dup;
            for (/* void */; /* void */; /* void */) {
                cJSON *dup_node = g_print_node(loop);
                cJSON_AddItemToArray(dup_array, dup_node);
                if (loop->dup) {
                    loop = loop->dup;
                } else {
                    break;
                }
            }
            cJSON_AddItemToObject(cur, "dup", dup_array);
        }
        cJSON_AddItemToArray(g_arr, cur);
        node = node->next;
    }
    log_dbg("\n\n");
    log_dbg("%s\n", cJSON_PrintUnformatted(g));
    // log_dbg("%s\n", cJSON_Print(g));
    cJSON_Delete(g);
}
void g_map_print() {
    cJSON *g;
    g = cJSON_CreateObject();
    cJSON_AddNumberToObject(g, "pkt_count", _data.pkt_count);
    cJSON_AddNumberToObject(g, "ip_count", _data.ip_count);
    cJSON_AddNumberToObject(g, "ipv4_count", _data.ipv4_count);
    cJSON_AddNumberToObject(g, "ipv6_count", _data.ipv6_count);
    cJSON *g_arr = cJSON_AddArrayToObject(g, "data");
    struct index *_index = _frame_map->index;
    for (/* void */; /* void */; /* void */) {
        if (!_index) {
            break;
        }
        struct prt_info *node = _index->entry->val;
        cJSON *cur = g_print_node(node);
        cJSON *next_frames = cJSON_AddArrayToObject(cur, "next_frames");
        cJSON_AddNumberToObject(cur, "dup_main_count", _index->entry->dup_count);
        for (; node->next_frame;) {
            cJSON *cur_next = g_print_node(node->next_frame);
            cJSON_AddItemToArray(next_frames, cur_next);
            node = node->next_frame;
        }
        cJSON_AddItemToArray(g_arr, cur);
        _index = _index->next;
    }
    log_dbg("\n\n");
    void *json = cJSON_PrintUnformatted(g);
    log_dbg("%s\n", json);
    // log_dbg("%s\n", cJSON_Print(g));

    char *msg = "<script> window._data = ";
    write(fd2, msg, strlen(msg));
    write(fd2, json, strlen(json));
    write(fd2, "</script>\n", 9);

    char buf[1024];
    for (;;) {
        size_t n = read(fd, &buf, 1024);
        if (n < 1) {
            break;
        }
        if (write(fd2, &buf, n) < 1) {
            break;
        }
    }
    fsync(fd2);
    close(fd);
    close(fd2);
    cJSON_Delete(g);
}
void handle_tcp() {
    struct index *_index = _frame_map->index;
    for (; _index;) {
        struct prt_info *_pi = _index->entry->val;
        struct prt_info *pi = _pi;
        for (; pi;) {
            int ret = IPPROTO_TCP;
            struct tcphdr *_tcphdr = (struct tcphdr *) (pi->tcp_udp_hdr);
            unsigned char *p = pi->data;
            raxIterator iter;
            raxStart(&iter, _rax);// Note that 'rt' is the radix tree pointer.
            size_t p_len = strlen((const char *) p);
            if (!p) break;
            if (pi->len < 1) goto next_frame;
            raxSeek(&iter, ">=", p, 1);
            while (raxNext(&iter)) {
                if (iter.key_len <= p_len && raxCompare(&iter, "==", p, iter.key_len)) {
                    ret = ((detec_pro_t)(iter.data))(pi);
                    _pi->protocol = pi->protocol;
                    _pi->print_message = pi->print_message;
                    goto next;
                }
            }
            raxStop(&iter);
        next_frame:
            pi = pi->next_frame;
        }
    next:
        _index = _index->next;
    }
}
/*
* @argv[0] file to parse
*/
int main(int argc, char *argv[]) {
    /* sig_handle func init */
    sig_init();
    /* init frame protocol routers */
    init_pro_detec();
    /* tcp group map init */
    _frame_map = dictCreate(10);
    int ret = EXIT_SUCCESS;
    fd = open(argv[2], O_RDONLY | O_CLOEXEC, 0666);
    if (argc < 4) {
        log_err("Please input : %s <pcap file name> <pcap template file> <result output file>\n", argv[0]);
        return 1;
    }
    if (fd == -1) {
        log_err("open file error %s", strerror(errno));
    } else {
        fd2 = open(argv[3], O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC | O_APPEND, 0666);
        if (fd2 == -1) {
            log_err("open file error %s", strerror(errno));
        }
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
    pcap_loop(p, -1, data_callback, (unsigned char *) p);
    prt_info_out();
    pcap_close(p);
    handle_tcp();
    g_map_print();
clean:
    fflush(stdout);
    fflush(stderr);
exit:
    return ret;
}
