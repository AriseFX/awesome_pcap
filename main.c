#include "main.h"

struct g_prt_info_data _data = {
    .head = NULL,
    .tail = NULL,
};
/*
* @argv[0] file to parse
*/
int main(int argc, char *argv[])
{
    sig_init();
    int ret = EXIT_SUCCESS;
    if (argc < 2)
    {
        log_err("Please input : %s <pcap file name>\n", argv[0]);
        return 1;
    }
    /*  log_init() */
    log_dbg("Open pcap %s\n", argv[1]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(argv[1], errbuf);

    if (p == NULL)
    {
        log_err("Error for pcap_open_offline :%s\n", errbuf);
        ret = EXIT_FAILURE;
        goto clean;
    }
    pcap_loop(p, -1, data_callback, NULL);
    prt_info_out();
    pcap_close(p);
clean:
    fflush(stdout);
    fflush(stderr);
exit:
    return ret;
}
