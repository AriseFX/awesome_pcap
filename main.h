#ifndef __MAIN_H__
#define __MAIN_H__


/* 本文件用于，  包含项目所有用到的头文件 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <linux/if_ether.h>     /*  帧 */
#include <arpa/inet.h>          /* ntoh */

#include <linux/ip.h>           /* IP报文 */
#include <netinet/in.h>

#include <linux/tcp.h>          /* TCP段 */
#include <linux/udp.h>          /* UDP段 */

#include <pcap/pcap.h>


#include "log.h"                /*  日志文件 */

#include "protocol_info.h"      /*  协议信息相关 */

#include "callback.h"           /* pcap loop 的回调函数接口 */

#include "protocol.h"           /*   协议支持的头文件 */

#ifdef  PRO_TYPES_SSH

#include "ssh.h"                /* ssh协议探测 */

#endif                          /* PRO_TYPES_SSH */


#endif                          /*__MAIN_H__ */
