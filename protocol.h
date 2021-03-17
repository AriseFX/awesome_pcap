#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#define PRO_UNKNOWN 0
#define PRO_TYPES_SSH 1
#define PRO_TYPES_TFTP 2
#define PRO_TYPES_NTP 3

/* 当前支持协议解析的最后协议， 当添加新协议的时候， 需要更改当前最后协议 */
#define PRO_LAST PRO_TYPES_NTP

/*  当前支持协议最大数量 */
#define PRO_TYPES_MAX (PRO_LAST + 1)

/*  协议标识， 顺序和定义支持对应协议保持一致, 添加新协议时， 添加该协议的标识，参考下述例子*/

#define PRO_STRINGS \
        "UNKNOWN",  \
            "SSH",  \
            "TFTP", \
            "NTP"

/* 完成对已识别应用协议的四元组保存 */

struct prt_info;

extern int pro_types_save(struct prt_info *pi, int types);

/**
 * 对与当前数据包， 和已知类型应用协议四元组，作对比，
 *  如果为已知类型， 返回1，
 *  如果不匹配已知类型， 返回0；
 */
extern int pro_types_cmp(struct prt_info *pi, int types);

#endif /* __PROTOCOL_H__ */
