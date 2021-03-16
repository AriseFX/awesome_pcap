#include "main.h"

int main(int argc, char *argv[]) {
    //从命令行读入 pcap文件
    if (argc < 2) {
        log_err("Please input : %s <pcap file name>\n", argv[0]);
        return 1;
    }
    /*  log_init() */
    /* 对分析的协议信息， 进行初始化 */
    prt_info_t *info = new_prt_info();
    if (info == NULL) {
        log_err("initial protocol info  failed\n");
        return 1;
    }
    log_dbg("Open pcap %s\n", argv[1]);
    //用于标示返回状态
    int ret = 0;
    //pcap 打开文件
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(argv[1], errbuf);

    if (p == NULL) {
        fprintf(stderr, "Error for pcap_open_offline %s:%s\n", argv[1], errbuf);
        ret = 1;
        goto err;
    }
    //data_callback种解析
    pcap_loop(p, -1, data_callback, (u_char *) info);
    pcap_close(p);
    prt_info_out(info);

    err:
    prt_info_free(info);
    /* log_end */
    return ret;
}
