#ifndef __LOG_H__
#define __LOG_H__


#include <stdio.h>
#include <stdlib.h>

/* 定义调试开关， 当DPI_DEBUG 为1时候， 打开调试， 为0时， 关闭调试信息输出 */
#define DPI_DEBUG 1

/**
 *  用来规划日志， 
 * 
 */
#define log_err(...)  printf(__VA_ARGS__)
#define log_info(...) printf(__VA_ARGS__)

/*  利用调试开关， 控制调试信息的输出 */

#if DPI_DEBUG

#define log_dbg(...)  do {                      \
        printf("%s:%s:%d\t", __FILE__, __func__, __LINE__); \
        printf(__VA_ARGS__);                                    \
}while(0)

#else

#define log_dbg(...)

#endif  /* DPI_DEBUG */

#endif  /* __LOG_H__ */
