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

/* Ethernet header */
struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader
{
  unsigned char iph_ihl : 4,       // IP header length
      iph_ver : 4;                 // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
      iph_offset : 13;             // Flags offset
  unsigned char iph_ttl;           // Time to Live
  unsigned char iph_protocol;      // Protocol type
  unsigned short int iph_chksum;   // IP datagram checksum
  struct in_addr iph_sourceip;     // Source IP address
  struct in_addr iph_destip;       // Destination IP address
};

/* Application header*/

struct appheader
{
  uint32_t timestamp;
  uint16_t total_length;
  union
  {
    uint16_t flags;
    uint16_t space : 3, c_flag : 1, s_flag : 1, t_flag : 1, status : 10;
  };
  uint16_t cache_control;
  uint16_t fill;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct ethheader *etr_header = (struct ethheader *)(packet);
  struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct ethheader));
  struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethheader) + (ip_header->iph_ihl * 4));
  struct appheader *app_header = (struct appheader *)(packet + sizeof(struct ethheader) + (ip_header->iph_ihl * 4) + (tcp_header->doff * 4));

  if (tcp_header-> psh != 1)
    return;

  FILE *fd;
  fd = fopen("323861021_207829813", "a+");

  app_header->flags = ntohs(app_header->flags);
  uint16_t cache_flag = ((app_header->flags >> 12) & 1);
  uint16_t steps_flag = ((app_header->flags >> 11) & 1);
  uint16_t type_flag = ((app_header->flags >> 10) & 1);

  char *source_ip = inet_ntoa(ip_header->iph_sourceip);
  char *dest_ip = inet_ntoa(ip_header->iph_destip);
  uint16_t source_port = ntohs(tcp_header->source);
  uint16_t dest_port = ntohs(tcp_header->dest);
  uint32_t timestamp = ntohl(app_header->timestamp);
  uint16_t total_length = ntohs(app_header->total_length);
  // app_header->status = htons(app_header->status);
  uint16_t status_code = app_header->status;
  uint16_t cach_control = ntohs(app_header->cache_control);

  uint8_t *data = (uint8_t *)(packet + sizeof(struct ethheader) + (ip_header->iph_ihl * 4) + (tcp_header->doff * 4) + 12);
  // uint8_t temp = data;

  fprintf(fd, "source ip = %s \n", source_ip);
  fprintf(fd, "dest ip = %s \n", dest_ip);
  fprintf(fd, "source port = %hu \n", source_port);
  fprintf(fd, "dest port = %hu \n", dest_port);
  fprintf(fd, "timestamp = %u\n", timestamp);
  fprintf(fd, "total length = %hu\n", total_length);
  fprintf(fd, "cache flag = %hu\n", cache_flag);
  fprintf(fd, "steps flag = %hu\n", steps_flag);
  fprintf(fd, "type flag = %hu\n", type_flag);
  fprintf(fd, "status code = %hu\n", status_code);
  fprintf(fd, "cach control = %hu\n", cach_control);

  fprintf(fd, "DATA:\n");
  for (int i = 0; i < total_length; i++)
  {
    if (!(i & 15))
      fprintf(fd, "\n%04X: ", i);

    fprintf(fd, "%02X ", ((unsigned char *)data)[i]);
  }

  fprintf(fd, "\n------------------\n");

  fclose(fd); // Close fd
}

int main()
{

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
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
