#ifndef __MAIN_H__
#define __MAIN_H__
/* void warning macro */
#define UNUSED(V) ((void)V)
#define STDOUT_FD 2
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <stddef.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <linux/if_ether.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netinet/in.h>

#include <linux/tcp.h>
#include <linux/udp.h>

#include <pcap/pcap.h>

#include "log.h"

#include "protocol_info.h"

#include "callback.h"

#include "protocol.h"

#include "debug.h"

#ifdef PRO_TYPES_SSH

#include "ssh.h"

#endif /* PRO_TYPES_SSH */

#endif /*__MAIN_H__ */
