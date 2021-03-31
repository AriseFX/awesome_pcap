#include "main.h"
#include "pmalloc.h"
#include <cJSON.h>

#ifdef PRO_TYPES_HTTP

#define CR '\r'
#define LF '\n'
#define BLANK ' '

int detec_http(struct prt_info *pi) {
    if (pi->data == NULL)
        return PRO_UNKNOWN;
    struct tcphdr *_tcphdr = (struct tcphdr *) pi->tcp_udp_hdr;

    struct iphdr *_iphdr = (struct iphdr *) pi->ipvnhdr;
    //TODO 抽出各协议详细的校验
    if ((ntohs(_iphdr->tot_len) - _iphdr->ihl * 4 - _tcphdr->doff * 4) < 5) {
        return PRO_UNKNOWN;
    }
    u_char *p = (u_char *) (pi->data);

    u_char *crlf_p = memchr(p, CR, 200);
    if (crlf_p == NULL || *(crlf_p + 1) != LF) {
        return PRO_UNKNOWN;
    }
    u_char **line = p_malloc((sizeof(u_char *) * 3) + 1);
    int16_t status_line_size = crlf_p - p;
    for (int i = 0, offset = 0, j = 0; i <= status_line_size; i++) {
        if (*(p + i) == BLANK || i == status_line_size) {
            int length = i - offset;
            u_char *token = p_malloc(length + 1);
            memcpy(token, p + offset, i - offset);
            *(token + length) = '\0';
            //++i for skip ''
            offset = ++i;
            line[j++] = token;
        }
    }
    struct http_request *request = p_malloc(sizeof(struct http_request));
    request->method = line[0];
    request->url = line[1];
    request->version = line[2];

    cJSON *usr = cJSON_CreateObject();
    cJSON_AddStringToObject(usr, "name", line[0]);
    cJSON_AddStringToObject(usr, "url", line[1]);
    cJSON_AddStringToObject(usr, "version", line[2]);

    char *out = cJSON_Print(usr);

    pi->protocol = "HTTP";
    pi->print_message = out;
    return PRO_TYPES_HTTP;
}

#endif /* PRO_TYPES_HTTP */
