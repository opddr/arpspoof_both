#ifndef SPOOFTOOL_H
#define SPOOFTOOL_H
#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <pthread.h>

class spooftool
{
    char requestbuf[1000],responsebuf[1000];
    pcap_t *hPcap;
public:
    spooftool(){}
    spooftool(char *interface, char *senderip, char *destip);
    void keep_spoofing();
};

#endif // SPOOFTOOL_H
