#include <pcap.h>
#include <stdio.h>

#define ETHER_ADDR_LEN 6

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

// void got_packet(u_char *args, const struct pcap_pkthdr *header,
//                 const u_char *packet)
// {
//   struct ethheader *eth = (struct ethheader *)packet;

//   if (ntohs(eth->ether_type) == 0x0800)
//   { // 0x0800 is IP type
//     struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

//     printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
//     printf("         To: %s\n", inet_ntoa(ip->iph_destip));

//     /* determine protocol */
//     switch (ip->iph_protocol)
//     {
//     case IPPROTO_TCP:
//       printf("   Protocol: TCP\n");
//       return;
//     case IPPROTO_UDP:
//       printf("   Protocol: UDP\n");
//       return;
//     case IPPROTO_ICMP:
//       printf("   Protocol: ICMP\n");
//       return;
//     default:
//       printf("   Protocol: others\n");
//       return;
//     }
//   }
// }

/* Ethernet header */
struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/*TCP header */
struct tcpheader
{
  uint16_t source_port;      // 16-bit source port number
  uint16_t destination_port; // 16-bit destination port number
  uint32_t sequence_number;  // 32-bit sequence number
  uint32_t acknowledgement;  // 32-bit acknowledgement number
  uint8_t data_offset : 4;   // 4-bit data offset and 4-bit reserved
  uint8_t flags;             // 8-bit flags
  uint16_t window;           // 16-bit window size
  uint16_t checksum;         // 16-bit checksum
  uint16_t urgent_pointer;   // 16-bit urgent pointer (if URG flag is set)
};

/* Application header*/
struct appheader
{
  uint32_t timestamp;
  uint16_t total_length;
  uint16_t saved:3, c_flag:1, s_flag:1, t_flag:1, status:10;
  uint16_t cache_control;
  uint16_t __;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct ethheader *etr_header = (struct ethheader *)(packet);
  struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct ethheader));
  struct tcpheader *tcp_header = (struct tcpheadear *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
  struct appheader *app_header = (struct appheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));

  FILE *fd;
  fd = fopen("323861021_207829813", "a+");
  fprintf(fd, "source ip = %s \n", inet_ntoa(ip_header->iph_sourceip));
  fprintf(fd, "dest ip = %s \n", inet_ntoa(ip_header->iph_destip));
  fprintf(fd, "source port = %u \n", ntohs(tcp_header->source_port));
  fprintf(fd, "dest port = %u \n", ntohs(tcp_header->destination_port));
  fprintf(fd, "timestamp = %u\n", ntohl(app_header->timestamp));
  fprintf(fd, "total length = %d\n", app_header->total_length);
  fprintf(fd, "cache flag = %d\n", app_header->c_flag);
  fprintf(fd, "steps flag = %d\n", app_header->s_flag);
  fprintf(fd, "type flag = %d\n", app_header->t_flag);
  fprintf(fd, "status code = %d\n", app_header->status);
  fprintf(fd, "cach control = %d\n", app_header->cache_control);
  fprintf(fd, "------------------\n");

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
