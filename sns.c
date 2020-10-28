// spoof
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

// sniff
#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>



// spoof
#define ipheader_len 20
#define icmpheader_len 8

// // sniff
#define SNAP_LEN 1518 /* default snap length (maximum bytes per packet to capture) */
#define SIZE_ETHERNET 14 /* ethernet headers are always exactly 14 bytes [1] */
#define ETHER_ADDR_LEN  6 /* Ethernet addresses are 6 bytes */

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)



// global vars
char victim[16];
char server[16];
uint32_t saved_seq_be = 0;
uint32_t saved_id_be = 0;
uint32_t saved_ip_ident = 0;
uint32_t flag = 0;

void spoof();


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


void got_icmp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */
    const struct sniff_ip *ip;              /* The IP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("\n\tCaptured packet #%d\t", count);
    count++;

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    if (ip->ip_p == IPPROTO_ICMP) {
        printf("\tProtocol: ICMP\n");
    }
    else {
        printf("Protocols other than ICMP are not supported in this program\n");
        return;
    }

    // parse packet
    char *capturedPacket = malloc(1024 * sizeof(char));
    capturedPacket = (char *) ip;
    struct icmpheader *icmpPacket = (struct icmpheader *) (capturedPacket + ipheader_len);
    struct ipheader *gotIp = (struct ipheader *)ip;
    
    // save header values
    strcpy(victim, inet_ntoa(ip->ip_src));
    strcpy(server, inet_ntoa(ip->ip_dst));
    saved_ip_ident = ntohs(ip->ip_id);
    saved_seq_be = ntohs(icmpPacket->icmp_seq);
    saved_id_be = ntohs(icmpPacket->icmp_id);

    // print info
    printf("\t=> From: %s\t", inet_ntoa(ip->ip_src));
    printf("\t=> To: %s\n", inet_ntoa(ip->ip_dst));
    printf("\t=> IPH offset: %d\n", ntohs(ip->ip_off));
    printf("\t=> IPH ident: %d\n", ntohs(ip->ip_id));
    printf("\t=> IPH Flags: %d\n", ntohs(gotIp->iph_flag));
    printf("\t=> icmp Id BE: %d\n", ntohs(icmpPacket->icmp_id));
    printf("\t=> icmp Id LE: %d\n", icmpPacket->icmp_id);
    printf("\t=> icmp SEQ BE: %d\n", ntohs(icmpPacket->icmp_seq));

    spoof(saved_seq_be, saved_id_be);
}



void spoof(int seq_BE, int id_BE)
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
    ip.iph_ident = htons(saved_ip_ident); 
    ip.iph_offset = 0;


    inet_aton(server, (struct in_addr*) &src_ip);
    inet_aton(victim, (struct in_addr*) &dst_ip);
    ip.iph_sourceip.s_addr = (in_addr_t) src_ip;
    ip.iph_destip.s_addr = (in_addr_t) dst_ip;


    icmp.icmp_type = 0; //0 echo reply //8 echo request
    icmp.icmp_code = 0;
    icmp.icmp_chksum = htons(0);
    icmp.icmp_id = htons(id_BE);
    icmp.icmp_seq = htons(seq_BE);


    memcpy(bufferPacket, &ip, ipheader_len);
    memcpy((bufferPacket + ipheader_len), &icmp, icmpheader_len);


    icmp.icmp_chksum = in_cksum((unsigned short *)(bufferPacket + ipheader_len), icmpheader_len);
    memcpy((bufferPacket + ipheader_len), &icmp, icmpheader_len);


    printf("\t\t=> Spoof from: %s\n", server);
    printf("\t\t=> Spoof to: %s\n", victim);
    printf("\t\t=> Spoofed ID (LE) sent back: %d\n", icmp.icmp_id);
    printf("\t\t=> Spoofed SEQ (LE) sent back : %d\n", icmp.icmp_seq);
    printf("\t\t=> Spoofed ID sent back : %d\n", ntohs(ip.iph_ident));

    send_raw_ip_packet((struct ipheader *) bufferPacket);

    printf("\n\t%s\n", "===========================================");

}



int main(int argc, char *argv[])
{
    printf("\n%s\n", "start sniffing");

    char *dev = NULL;           /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */
    char filter_exp[] = "icmp[icmptype] == icmp-echo";       /* filter expression [3] */
    struct bpf_program fp;          /* compiled filter program (expression) */
    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int num_packets = 100;           /* number of packets to capture */


    if (argc == 2) {
        dev = argv[1];
    }
    else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        exit(EXIT_FAILURE);
    }
    else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
            exit(EXIT_FAILURE);
        }
    }
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
        net = 0;
        mask = 0;
    }


    printf("\nDevice: %s\n", dev);
    printf("mask: %d\n", mask);
    printf("net: %d\n", net);
    printf("Number of packets to spoof: %d\n", 10);
    printf("Filter expression: %s\n", filter_exp);


    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 2000, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    } 

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }


    /* now we can set our callback function */
    pcap_loop(handle, 10, got_icmp_packet, NULL);


    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);


    printf("\nCapture complete.\n");

    return 0;
}

