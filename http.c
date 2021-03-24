#include "main.h"
#include "pmalloc.h"

#ifdef PRO_TYPES_HTTP

#define CRLF '\r\n'
#define BLANK ' '

int detec_http(struct prt_info *pi) {
    if (pi->tcp_udp_hdr == NULL)
        return 0;
    struct tcphdr *_tcphdr = (struct tcphdr *) pi->tcp_udp_hdr;

    struct iphdr *_iphdr = (struct iphdr *) pi->ipvnhdr;
    //TODO 抽出各协议详细的校验
    if ((ntohs(_iphdr->tot_len) - _iphdr->ihl * 4 - _tcphdr->doff * 4) < 5) {
        return 0;
    }
    unsigned char *p = (unsigned char *) _tcphdr + _tcphdr->doff * 4;
    unsigned char *crlf_p = memchr(p, CRLF, 200);
    if (crlf_p != NULL) {
        unsigned char **line = p_malloc(sizeof(void *) * 3);
        int16_t status_line_size = crlf_p - p - 1;
        for (int i = 0, offset = 0, j = 0; i <= status_line_size; i++) {
            if (*(p + i) == BLANK || i == status_line_size) {
                unsigned char *token = p_malloc(i);
                memcpy(token, p + offset, i - offset);
                //++i for skip ''
                offset = ++i;
                line[j++] = token;
            }
        }
        struct http_request *request = p_malloc(sizeof(struct http_request));
        request->method = line[0];
        request->url = line[1];
        request->version = line[2];
        return 1;
    }
    return 0;
}

#endif /* PRO_TYPES_HTTP */
