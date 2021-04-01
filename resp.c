#include "resp.h"
#include "pmalloc.h"

int detec_resp(struct prt_info *pi) {
    if (pi->tcp_udp_hdr == NULL)
        return PRO_UNKNOWN;
    pi->protocol = "RESP";
    // pi->data
    void *_data = p_malloc(strlen(pi->data));
    memcpy(_data, pi->data, strlen(pi->data));
    pi->print_message = _data;
    return PRO_TYPES_RESP;
}
