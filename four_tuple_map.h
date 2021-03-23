#ifndef __Q_MAP_H__
#define __Q_MAP_H__
#include "main.h"
#include "protocol_info.h"
#define MAP_HASH_DEFAULT_SIZE 10
/*
* cause this map is not used to store the temporary data
* so no need to resize it
*/
struct entry {
    struct entry *next;
    unsigned int
            /* ip */
            saddr,
            daddr;
    unsigned short int
            /* port */
            source,
            dest;
    struct prt_info *val;
    long key;
};

struct q_map {
    unsigned int _size;// bucket nums
    /*
  * use _bitcount(saddr<<16^daddr<<16|source<<8|dest) % _size to caculate offset
  */
    struct entry **bucket;
};
/* API */
struct q_map *dictCreate(unsigned int);
void q_free(struct q_map *);
/* add to the dict, while dup frame, add to the target prt_info->dup tail */
int dict_add(struct q_map *, struct prt_info *);
/* search the first frame when exists dup frames */
struct prt_info *dict_search(struct q_map *, struct prt_info *);
#endif /* __Q_MAP_H__ */