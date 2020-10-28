/* Must be root or SUID 0 to open RAW socket */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include "seedheaders.h"
#include <stdlib.h>



#define ipheader_len 20
#define icmpheader_len 8



/****************************************************
  Calculate an internet checksum
*****************************************************/
unsigned short in_cksum (unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum) adds sequential 16 bit
     * words to it, and at the end, folds back all the carry bits from the
     * top 16 bits into the lower 16 bits
     */

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *) (&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                    // add carry
    return (unsigned short) (~sum);
}



/********************************************************************
  TCP checksum is calculated on the pseudo header, which includes
  the TCP header and data, plus some part of the IP header.  Therefore,
  we need to construct the pseudo header first
  ********************************************************************/

/* Pseudo TCP header */
struct pseudo_tcp
{
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcphdr tcp;
    char payload[1500];
};

unsigned short calculate_tcp_checksum(struct ipheader *ip) {
    struct tcphdr *tcp = (struct tcphdr *) ((u_char *)ip + sizeof(struct ipheader));
    int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);


    /* pseudo tcp header for checksum comp */
    struct pseudo_tcp p_tcp;
    memset (&p_tcp, 0x0, sizeof(struct pseudo_tcp));

    p_tcp.saddr = ip->iph_sourceip.s_addr;
    p_tcp.daddr = ip->iph_destip.s_addr;
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_TCP;
    p_tcp.tcpl = htons(tcp_len);
    memcpy(&p_tcp.tcp, tcp, tcp_len);


    return (unsigned short) in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}


void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // step 1: Create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);


    // step 2: Set socket options
    setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));


    // step 3: Provided destination information
    dest_info.sin_family = AF_INET;  // internet protocol
    dest_info.sin_addr = ip->iph_destip;


    // step 4: Send the packet out
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}




void spoof()
{
    int src_ip, dst_ip;
    char bufferPacket[1024];
    struct ipheader ip;
    struct icmpheader icmp;

    printf("\t\t%s\n", "Sending back spoofed packets...");
    ip.iph_ihl = ipheader_len / sizeof (int);
    ip.iph_ver = 4;
    ip.iph_tos = 0;
    ip.iph_len = htons(ipheader_len + icmpheader_len);
    ip.iph_ident = htons(0);
    ip.iph_ttl = 64;
    ip.iph_protocol = 1;
    ip.iph_chksum = htons(0);
    ip.iph_ident = htons(0); 
    ip.iph_offset = 0;


    inet_aton("10.0.2.9", (struct in_addr*) &src_ip);
    inet_aton("204.79.197.200", (struct in_addr*) &dst_ip);
    ip.iph_sourceip.s_addr = (in_addr_t) src_ip;
    ip.iph_destip.s_addr = (in_addr_t) dst_ip;


    icmp.icmp_type = 8; // echo request
    icmp.icmp_code = 0;
    icmp.icmp_chksum = htons(0);
    icmp.icmp_id = htons(0);
    icmp.icmp_seq = htons(0);


    memcpy(bufferPacket, &ip, ipheader_len);
    memcpy((bufferPacket + ipheader_len), &icmp, icmpheader_len);


    icmp.icmp_chksum = in_cksum((unsigned short *)(bufferPacket + ipheader_len), icmpheader_len);
    memcpy((bufferPacket + ipheader_len), &icmp, icmpheader_len);


    printf("\t\t=> Spoof from: %s\n", "10.0.2.9");
    printf("\t\t=> Spoof to: %s\n", "204.79.197.200");
    printf("\t\t=> Spoofed ID (LE) sent back: %d\n", icmp.icmp_id);
    printf("\t\t=> Spoofed SEQ (LE) sent back : %d\n", icmp.icmp_seq);
    printf("\t\t=> Spoofed ID sent back : %d\n", ntohs(ip.iph_ident));

    send_raw_ip_packet((struct ipheader *) bufferPacket);

    printf("\n\t%s\n", "===========================================");

}


int main(int argc, char *argv[])
{
    spoof();

    return 0;
}
