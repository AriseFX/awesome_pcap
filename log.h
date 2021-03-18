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
#define log_err(...) fprintf(stderr, __VA_ARGS__)
#define log_info(...) fprintf(stdout, __VA_ARGS__)

/*  利用调试开关， 控制调试信息的输出 */

#if DPI_DEBUG

#define log_dbg(...)                                                  \
        do                                                            \
        {                                                             \
                log_info("%s:%d:%s\t", __FILE__, __LINE__, __func__); \
                log_info(__VA_ARGS__);                                \
        } while (0)

#else

#define log_dbg(...)

#endif /* DPI_DEBUG */

#endif /* __LOG_H__ */
