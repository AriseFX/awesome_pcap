#include "main.h"
/*
* @argv[0] file to parse
*/
int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;
    if (argc < 2)
    {
        log_err("Please input : %s <pcap file name>\n", argv[0]);
        return 1;
    }
    /*  log_init() */
    prt_info_t *info = new_prt_info();
    if (info == NULL)
    {
        log_err("initial protocol info  failed\n");
        ret = EXIT_FAILURE;
        goto exit;
    }
    log_dbg("Open pcap %s\n", argv[1]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(argv[1], errbuf);

    if (p == NULL)
    {
        log_err("Error for pcap_open_offline :%s\n", errbuf);
        ret = EXIT_FAILURE;
        goto clean;
    }
    pcap_loop(p, -1, data_callback, (u_char *)info);
    prt_info_out(info);
clean:
    prt_info_free(info);
    fflush(stdout);
    fflush(stderr);
exit:
    pcap_close(p);
    return ret;
}
