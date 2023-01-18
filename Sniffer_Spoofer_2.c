#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>

#define ICMP_ECHOREPLY		0

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};
/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void send_raw_ip_packet(struct ip *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->ip_dst;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->ip_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    
    struct ipheadr *ip_header = (struct ipheader *)packet;
    struct icmpheadr *icmp_header = (struct icmpheader *)(packet + sizeof(struct ip));


    // Update the destination IP in the new packet
    struct ipheader *new_ip_header = (struct ip *)packet;
    struct icmpheader *new_icmp_header = (struct icmp *)(packet + new_ip_header->iph_len*4);
    new_icmp_header->icmp_type = ICMP_ECHOREPLY;

    struct in_addr temp = new_ip_header->iph_sourceip;
    new_ip_header->iph_sourceip = new_ip_header->iph_destip;
    new_ip_header->iph_destip = temp;
    
    char *source_ip = inet_ntoa(new_ip_header->iph_sourceip);
    char *dest_ip = inet_ntoa(new_ip_header->iph_destip);
    printf( "source ip = %s \n", source_ip);
    printf( "dest ip = %s \n", dest_ip);

    // Send the packet
    send_raw_ip_packet(new_ip_header);
}

int main()
{

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}