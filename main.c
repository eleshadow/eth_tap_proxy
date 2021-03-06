#include "head.h"

int tap_fd = 0;

void anlyze_pkt(char *interface, struct pcap_pkthdr *pkthdr, const u_char *packet)
{
#if 0
    struct ethhdr *eth = (struct ethhdr *)packet;
    printf("receive from %s, length %d\n", interface, pkthdr->len);
    printf("packet proto %04x\n", htons(eth->h_proto));
#endif

    write(tap_fd, packet, pkthdr->len);
}

int main(int argc, char *argv[])
{
    pthread_t thread_get_packet  = 0;
    pthread_t thread_send_packet = 0;
    struct input_dev_list dev_list;
    int ret = 0;

    dev_list.count = argc - 1;
    dev_list.dev_name_list = argv + 1;

    tap_fd = init_tap_interface();

    if (dev_list.count <= 0 || tap_fd <= 0)
    {
        return OK;
    }

    ret = pthread_create(&thread_send_packet, NULL, send_packet, (void*)argv[1]);
    if (ret != OK)
    {
        printf("creat send_packet_thread fail\n");
        return ERROR;
    }

    ret = pthread_create(&thread_get_packet, NULL, get_packet, (void*)&dev_list);
    if (ret != OK)
    {
        printf("creat get_packet thread fail\n");
        return ERROR;
    }

    while(1)
    {
        int ret_get  = -1;
        int ret_send = -1;

        if (ret_get != 0)
        {
            ret_get  = pthread_join(thread_get_packet, NULL);
        }

        if (ret_send != 0)
        {
            ret_send = pthread_join(thread_send_packet, NULL);
        }

        if ((ret_send == 0) && (ret_get == 0))
        {
            break;
        }
    }
        
    return OK;
}
