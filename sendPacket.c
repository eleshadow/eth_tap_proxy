#include <sys/socket.h>
#include <string.h>
#include "head.h"

#define BUF_SIZE 4096

void *send_packet(void *arg)
{
    char *devname = arg;
    struct sockaddr addr = {0};
    int fdSocket   = 0;
    char buf[BUF_SIZE] = {'\0'};
    
    fdSocket = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ALL));
    if (fdSocket < 0)
    {
        printf("creat socket packet error\n");
        pthread_exit(NULL);
    }

    memset(&addr, 0, sizeof(addr));
    strcpy(addr.sa_data, devname);

    while (1)
    {
        int send_len = 0;
        int packet_len = 0;
        
        packet_len = read(tap_fd, buf, BUF_SIZE);
        if (packet_len < 0)
        {
            printf("%s read error\n", __func__);
        }

        send_len = sendto(fdSocket, buf, packet_len, 0, &addr, sizeof(addr));
        if (send_len < 0)
        {
            printf("%s send error\n", __func__);
        }
    }

    pthread_exit(NULL);
}
