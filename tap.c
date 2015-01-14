#include <stdio.h>
#include <error.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

int tun_create(char *dev, int flags)
{
    struct ifreq ifr;
    int fd, err;

    assert(dev != NULL);

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
        return fd;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags |= flags;

    if (*dev != '\0')
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

int set_if_flags(char *ifname, short flags)
{
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("create socket error");
        return -1;
    }

    /* set ip address */
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0 ) {
        perror("SIOCSIFADDR");
        close(sockfd);
        return -1;
    }

    ifr.ifr_flags |= flags;

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0 ) {
        perror("SIOCSIFADDR");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

int set_if_addr(char *ifname, char *ipaddr)
{
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("create socket error");
        return -1;
    }

    /* set ip address */
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);

    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, ipaddr, &sin->sin_addr);

    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0 ) {
        perror("SIOCSIFADDR");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

int init_tap_interface()
{
    int tun;
    char tun_name[IFNAMSIZ];

    tun_name[0] = '\0';
    tun = tun_create(tun_name, IFF_TAP | IFF_NO_PI);

    if (tun < 0) 
    {
        perror("tun_create");
        return -1;
    }
    printf("TUN name is %s\n", tun_name);

    set_if_flags(tun_name, IFF_UP);
#if 0
    set_if_addr(tun_name, "192.168.100.1");
#endif

    return tun;
}
#if 0
int main(int argc, char *argv[])
{
    int tun, ret;
    char tun_name[IFNAMSIZ];
    unsigned char buf[4096];

    tun_name[0] = '\0';
    tun = tun_create(tun_name, IFF_TAP | IFF_NO_PI);

    if (tun < 0) 
    {
        perror("tun_create");
        return 1;
    }
    printf("TUN name is %s\n", tun_name);

    set_if_flags(tun_name, IFF_UP);
    set_if_addr(tun_name, "192.168.100.1");

    while (1) 
    {
        int i = 0;

        ret = read(tun, buf, sizeof(buf));
        if (ret < 0)
            break;

        printf("receive a packet\n");

        for (i=0; i<ret; i++)
        {
            if ((i%8 == 0) && (i != 0))
            {
                printf("\n");
            }

            printf("0x%02x ", buf[i]);
        }

        printf("\n");
    }

    return 0;
}
#endif
