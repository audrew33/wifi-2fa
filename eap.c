#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  struct ether_header *eth_header;
  struct ip *ip_header;
  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  struct iwreq *wireless_info; // For WiFi information
  int ip_header_length;

  eth_header = (struct ether_header *)packet;

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    // Point to the IP header.
    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    ip_header_length = ip_header->ip_hl * 4;

    // Determine the transport protocol.
    if (ip_header->ip_p == IPPROTO_TCP) {
      // Check for TCP packets
      tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                     ip_header_length);
      printf("TCP Packet\n");
      printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
      printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
      printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
      printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
      // Check for UDP packets
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
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_EAPOL) {
    // Check for EAP packets (used in WiFi authentication)
    printf("EAP Packet\n");
    // Additional EAP processing logic can be added here
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IEEE802_11) {
    // Check for 802.11 frames (used in WiFi authentication)
    printf("802.11 Frame\n");
    // Additional 802.11 frame processing logic can be added here
  }
  printf("\n");
}
