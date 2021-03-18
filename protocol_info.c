/**
 * 完成对协议信息的初始化， 和相关操作
 * 
 */
#include "main.h"
#include "pmalloc.h"

static char *pro_string[PRO_TYPES_MAX] = {
    PRO_STRINGS};

/**
 * 对协议信息的初始化
 * @return 初始化失败，返回NULL
 *         成功，返回prt_info_t类型指针
 */
prt_info_t *new_prt_info(void)
{
    prt_info_t *pi = p_malloc(sizeof(*pi));
    memset(pi, 0, sizeof(*pi));

    /* 初始化应用协议探测引擎 */

    /* ssh协议探测 */
#ifdef PRO_TYPES_SSH
    pi->pro_detec[PRO_TYPES_SSH].flag = FLAG_TCP;
    pi->pro_detec[PRO_TYPES_SSH].pro_detec = detec_ssh;
#endif /* PRO_TYPES_SSH */

    /* ... 按需添加 */

    return pi;
}

/* 对协议信息的 释放 */

int prt_info_free(prt_info_t *pi)
{
    p_free(pi);
    return 0;
}

/* 对协议信息 输出 */
int prt_info_out(const prt_info_t *pi)
{
    /*  统计报文数量 */
    log_info("\nPacket: \n\n");
    log_info("\t Packet count: %d\n ", pi->pkt_count);
    log_info("\t IP packet  count: %d\n ", pi->ip_count);
    log_info("\t IPV4 packet  count: %d\n ", pi->ipv4_count);

    /* 输出已探测应用协议的包个数 */

    log_info("\n\n Application Protocol : \n\n");
    int i;
    for (i = 1; i < PRO_TYPES_MAX; i++)
    {
        if (pi->app_pro_count[i] != 0)
        {
            log_info("\t%s:%u\n", pro_string[i], pi->app_pro_count[i]);
        }
    }

    /* 输出未知类型的数据包数量 */
    log_info("\t%s:%u\n", pro_string[0], pi->app_pro_count[0]);

    return 0;
}
