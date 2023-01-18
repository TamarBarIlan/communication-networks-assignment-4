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
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


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
    struct ip *ip_header = (struct ip *)packet;
    struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ip));

    unsigned char new_packet[ntohs(ip_header->ip_len)];

    // Copy the entire original packet into the new packet
    memcpy(new_packet, packet, ntohs(ip_header->ip_len));

    // Update the destination IP in the new packet
    struct ip *new_ip_header = (struct ip *)new_packet;
    new_ip_header->ip_dst = ip_header->ip_src;
    new_ip_header->ip_src = ip_header->ip_dst;

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
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}
