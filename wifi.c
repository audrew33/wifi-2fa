#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#ifndef ETHERTYPE_PAE
#define ETHERTYPE_PAE 0x888e /* EAPOL PAE/802.1x */
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800 /* IP protocol */
#endif

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  // Extract the Ethertype.
  uint16_t ethertype = ntohs(*((uint16_t *)(packet + 12)));

  if (ethertype == ETHERTYPE_PAE) {
    printf("EAPOL Packet\n");
    // Extract and print information from the EAPOL packet.
    // Additional EAPOL packet processing logic can be added here.
  }
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
