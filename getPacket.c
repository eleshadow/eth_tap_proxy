#include "head.h"

int pcapFd_max = 0;
fd_set fdRead;
fd_set fdBack;

struct pcap_entry
{
    int fd;
    pcap_t *pcap;
    char *interface;
    struct pcap_entry* next;
} *pcap_list_head = NULL;

void pcap_entry_add(int pcapFd, pcap_t *pcap, char *interface)
{
    struct pcap_entry *temp = malloc(sizeof(struct pcap_entry));
    temp->fd = pcapFd;
    temp->pcap = pcap;
    temp->interface = interface;
    temp->next = pcap_list_head;
    pcap_list_head = temp;
}

struct pcap_entry *get_pcap_entry_by_fd(int fd)
{
    struct pcap_entry *temp = pcap_list_head;

    while (temp != NULL)
    {
        if (temp->fd == fd)
        {
            break;
        }
        else
        {
            temp = temp->next;
        }
    }

    return temp;
}
 
void pcap_entry_close()
{
    while (pcap_list_head != NULL)
    {
        struct pcap_entry *temp = pcap_list_head;
        pcap_close(pcap_list_head->pcap);
        pcap_list_head = pcap_list_head->next;
        free(temp);
    }
}

void pcap_select_fd_add(pcap_t *pcap)
{
    int pcapFd = pcap_get_selectable_fd(pcap);

    FD_SET(pcapFd, &fdRead);
    FD_SET(pcapFd, &fdBack);

    pcapFd_max = pcapFd_max > pcapFd ? pcapFd_max : pcapFd;  
}

void recover_pcap_fd()
{
    int  i = 0;

    for (i=0; i <=pcapFd_max; i++)
    {
        if (FD_ISSET(i, &fdBack))
        {
            FD_SET(i, &fdRead);
        }
    }
}

void *get_packet(void *arg)
{
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct input_dev_list *pdev_list = arg;

    FD_ZERO(&fdRead);

    for (i = 0; i < pdev_list->count; i++)
    {
        pcap_t *pcap = pcap_open_live(pdev_list->dev_name_list[i], 65535, 1, 0, errbuf);
        if (pcap == NULL)
        {
            printf("pcap_open_live error: %s\n", errbuf);
            pthread_exit(NULL);
        }

        pcap_setnonblock(pcap, TRUE, errbuf);
        pcap_select_fd_add(pcap);
        pcap_entry_add(pcap_get_selectable_fd(pcap), pcap, pdev_list->dev_name_list[i]);
    }

    while (1)
    {
        select(pcapFd_max + 1, &fdRead, NULL, NULL, NULL);

        for (i = 0; i <= pcapFd_max; i++)
        {
            if (FD_ISSET(i, &fdRead))
            {
                struct pcap_pkthdr pktHeader;

                struct pcap_entry *pentry = get_pcap_entry_by_fd(i);
                if (pentry == NULL)
                {
                    printf("search pcap error\n");
                }

                const u_char * buf = pcap_next(pentry->pcap, &pktHeader);
                if (buf == NULL)
                {
                    continue;
                }

                anlyze_pkt(pentry->interface, &pktHeader, buf);
            }
        }

        recover_pcap_fd();
    }

    pcap_entry_close();

    pthread_exit(NULL);
}
