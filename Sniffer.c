#include <pcap.h>
#include <stdio.h>

#define ETHER_ADDR_LEN 16

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
  u_short th_sport;    /* source port */
  u_short th_dport;    /* destination port */
  unsigned int th_seq; /* sequence number */
  unsigned int th_ack; /* acknowledgement number */
  u_short th_win;      /* window */
  u_short th_sum;      /* checksum */
  u_short th_urp;      /* urgent pointer */
};

/* Application header*/
struct appheader
{
  uint32_t timestamp;
  uint16_t total_length;
  int16_t cache_flag;
  int16_t staps_flag;
  int16_t type_flag;
  int16_t status_code;
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
  fd = fopen("323861021_207****", "w");

  fprintf(fd, "source ip = %s \n", inet_ntoa(ip_header->iph_sourceip));
  fprintf(fd, "dest ip = %s \n", inet_ntoa(ip_header->iph_destip));
  fprintf(fd, "source port = %d \n", tcp_header->th_sport);
  fprintf(fd, "dest port = %d \n", tcp_header->th_dport);
  fprintf(fd, "timestamp = %d\n", app_header->timestamp);
  fprintf(fd, "total length = %d\n", app_header->total_length);
  fprintf(fd, "cache flag = %d\n", app_header->cache_flag);
  fprintf(fd, "steps flag = %d\n", app_header->staps_flag);
  fprintf(fd, "type flag = %d\n", app_header->type_flag);
  fprintf(fd, "status code = %d\n", app_header->status_code);
  fprintf(fd, "cach control = %d\n", app_header->cache_control);

  fclose(fd);
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
