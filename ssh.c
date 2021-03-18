#include "main.h"
#include "ssh.h"

#ifdef  PRO_TYPES_SSH

/* 完成， 对ssh协议的探测，
 * 如果是ssh协议，返回1，如果不是ssh， 返回0  */

int detec_ssh(struct prt_info *pi) {
    /* tcphdr 为NULL ， 不处理 */
    // if (pi->tcphdr == NULL)
    //     return 0;

    // /*  应用数据小于5， 返回 */

    // /* 应用数据长度 = ip总长 - ip heaer - tcp-header  > 0 ， */
    // if ((ntohs(pi->iphdr->tot_len) - pi->iphdr->ihl * 4 - pi->tcphdr->doff * 4) < 5)
    //     return 0;

    // /*  如果应用中， 包括"SSH-" , 我们认为是 ssh协议 */
    // char *p = (char *) pi->tcphdr + pi->tcphdr->doff * 4;
    // if (strncmp(p, "SSH-", 4) == 0) {
    //     /* 保存，ssh协议的四元组 */
    //     pro_types_save(pi, PRO_TYPES_SSH);
    //     return 1;
    // }

    // if (pro_types_cmp(pi, PRO_TYPES_SSH) == 1)
    //     return 1;

    // /* ..... 如果是ssh， return 1; */
    return 0;
}


#endif  /* PRO_TYPES_SSH */
