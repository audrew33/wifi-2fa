#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  struct ether_header *eth_header;
  struct ip *ip_header;
  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  int ip_header_length;

  eth_header = (struct ether_header *)packet;

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    // Point to the IP header.
    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    ip_header_length = ip_header->ip_hl * 4;

    // Determine the transport protocol.
    if (ip_header->ip_p == IPPROTO_TCP) {
      tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                     ip_header_length);
      printf("TCP Packet\n");
      printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
      printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
      printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
      printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
      udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) +
                                     ip_header_length);
      printf("UDP Packet\n");
      printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
      printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
      printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
      printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
    }
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    printf("ARP Packet\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
    printf("Reverse ARP Packet\n");
  }
  printf("\n");
}

int main() {
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  // Get a suitable network device (you can specify a different device name).
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Device not found: %s\n", errbuf);
    return 1;
  }

  printf("Device: %s\n", dev);

  // Open the device for packet capture.
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Error opening device: %s\n", errbuf);
    return 1;
  }

  // Start packet capture and set the callback function.
  pcap_loop(handle, 0, packet_handler, NULL);

  // Close the capture handle.
  pcap_close(handle);

  return 0;
}
