#include "four_tuple_map.h"
#include "pmalloc.h"

static const int S[] = {1, 2, 4, 8, 16};// Magic Binary Numbers
static const int B[] = {
        0x55555555,
        0x33333333,
        0x0F0F0F0F,
        0x00FF00FF,
        0x0000FFFF};
/*
* http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
*/
static inline long _bitcount(long v) {
    unsigned long c;
    c = v - ((v >> 1) & B[0]);
    c = ((c >> S[1]) & B[1]) + (c & B[1]);
    c = ((c >> S[2]) + c) & B[2];
    c = ((c >> S[3]) + c) & B[3];
    c = ((c >> S[4]) + c) & B[4];
    return c;
}
struct q_map *dictCreate(unsigned int size) {
    struct q_map *ptr = p_calloc(1, sizeof(struct q_map));
    ptr->_size = size == 0 ? MAP_HASH_DEFAULT_SIZE : size;
    struct entry **bucket = p_calloc(1, ptr->_size * sizeof(struct entry *));
    ptr->bucket = bucket;
    return ptr;
}
void q_free(struct q_map *qm) {
    if (!qm)
        return;
    unsigned int i;
    for (i = 0; i < qm->_size; ++qm) {
        if (qm->bucket[i]) {
            for (;;) {
                struct entry *cur = qm->bucket[i];
                if (!cur) {
                    break;
                }
                struct entry *next = cur->next;
                p_free(cur);
                cur = next;
            }
        }
    }
    p_free(qm->bucket);
    p_free(qm);
}

int dict_add(struct q_map *qm, struct prt_info *pi) {
    if (!qm || !pi)
        return -1;
    long base = 0;
    unsigned int saddr = 0, daddr = 0;
    unsigned short source = 0, dest = 0;
    if (ntohs(pi->ethhdr->h_proto) == ETH_P_IP) {
        struct iphdr *_iphdr = (struct iphdr *) (pi->ipvnhdr);
        saddr = _iphdr->saddr;
        daddr = _iphdr->daddr;
    } /* else {} */// TODO ipv6

    base |= ((long) (saddr ^ daddr) << 8);
    if (pi->istcp) {
        struct tcphdr *_tcphdr = (struct tcphdr *) (pi->tcp_udp_hdr);
        source = _tcphdr->source;
        dest = _tcphdr->dest;
    } /* else {} */// TODO udp
    else {
        struct udphdr *_udphdr = (struct udphdr *) (pi->tcp_udp_hdr);
        source = _udphdr->source;
        dest = _udphdr->dest;
    }
    if (saddr < daddr) {
        unsigned int tmp = saddr;
        saddr = daddr;
        daddr = tmp;
    }
    if (source < dest) {
        unsigned short tmp = source;
        source = dest;
        dest = tmp;
    }
    base |= (long) (source ^ dest);
    int index = _bitcount(base) % qm->_size;
    struct entry *_entry = qm->bucket[index];
    struct entry *_tail = NULL;
    if (_entry) {
        /* do search */
        for (; _entry && _entry->key != base;) {
            _tail = _entry;
            _entry = _entry->next;
        }
        if (_entry) {
            /*
             * full check
             */
            for (; _entry && (_entry->source != source ||
                              _entry->dest != dest ||
                              _entry->saddr != saddr ||
                              _entry->daddr != daddr);) {
                _tail = _entry;
                _entry = _entry->next;
            }
        }
    }
    if (!_entry) {
        _entry = p_malloc(sizeof(struct entry));
        _entry->saddr = saddr;
        _entry->daddr = daddr;
        _entry->source = source;
        _entry->dest = dest;
        _entry->next = NULL;
        _entry->val = pi;
        _entry->key = base;
        if (!_tail) {
            qm->bucket[index] = _entry;
        } else {
            _tail->next = _entry;
        }
    } else {
        /* 
         * if protocol is tcp
         * we need to check seq & ack to find out if this frame is duplicated
         */
        struct prt_info *val = _entry->val;
        for (;;) {
            if (val->next_frame) {
                val = val->next_frame;
            } else {
                break;
            }
        }
        val->next_frame = pi;
    }
    /* finished */
}