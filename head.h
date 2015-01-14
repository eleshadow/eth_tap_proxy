#ifndef _HEADER_H_
#define _HEADER_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <sys/select.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <pthread.h>

#define TRUE   1
#define FALSE  0
#define OK     0
#define ERROR -1

struct input_dev_list{
    int count;
    char **dev_name_list;
};

extern int init_tap_interface();
extern void anlyze_pkt(char *interface, struct pcap_pkthdr *pkthdr, const u_char *packet);
extern void *get_packet(void *arg);

#endif /* _HEADER_H_ */
