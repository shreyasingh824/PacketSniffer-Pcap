#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void extractCredentials(const char *http_data) {
    char *uname = strstr(http_data, "uname=");
    char *pass = strstr(http_data, "pass=");
    char *cookie = strstr(http_data, "Cookie:");

    if (uname) {
        printf("Username: %s\n", uname + 6); // Skip "uname=" prefix
    }

    if (pass) {
        printf("Password: %s\n", pass + 5); // Skip "pass=" prefix
    }

    if (cookie) {
        printf("Cookie: %s\n", cookie + 7); // Skip "Cookie:" prefix
    }
}

void callback(unsigned char *arg, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    int i = 0;
    static int count = 0;
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;
    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    int version = (((*ip_header) & 0xF0) >> 4);
    ip_header_length = ip_header_length * 4;
    u_char protocol = *(ip_header + 9);

    tcp_header = packet + ethernet_header_length + ip_header_length;

    if (*(tcp_header + 3) == 80) {
        tcp_header_length = (((*(tcp_header + 12)) & 0xF0) >> 4);
        tcp_header_length = tcp_header_length * 4;
        int total_header_size = ethernet_header_length + ip_header_length + tcp_header_length;
        payload_length = pkthdr->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
        payload = packet + total_header_size;

        if (payload_length > 0) {
            const u_char *temp_pointer = payload;
            char *http_data = (char *)malloc(payload_length + 1);
            int byte_count = 0;

            // Copy payload data to http_data
            while (byte_count < payload_length) {
                http_data[byte_count] = *temp_pointer;
                temp_pointer++;
                byte_count++;
            }
            http_data[byte_count] = '\0';

            // Print packet information
            printf("Packet %d:\n", ++count);
            printf("Ethernet Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_header->ether_shost[0], eth_header->ether_shost[1],
                   eth_header->ether_shost[2], eth_header->ether_shost[3],
                   eth_header->ether_shost[4], eth_header->ether_shost[5]);
            printf("Ethernet Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_header->ether_dhost[0], eth_header->ether_dhost[1],
                   eth_header->ether_dhost[2], eth_header->ether_dhost[3],
                   eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)(ip_header + 12)));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr*)(ip_header + 16)));
            printf("Source Port (TCP): %d\n", ntohs(*(uint16_t*)(tcp_header + 0)));
            printf("Destination Port (TCP): %d\n", ntohs(*(uint16_t*)(tcp_header + 2)));
            printf("HTTP Data:\n");

            // Print HTTP payload
            printf("%s\n", http_data);

            // Extract credentials and cookies
            extractCredentials(http_data);

            free(http_data);
        }
    }
}


int main(int argc, char **argv) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program fp;
    bpf_u_int32 pNet;
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    
    // Check for command-line arguments
    if (argc != 3) {
        printf("\nInsufficient Arguments \nUsage: %s [protocol][number-of-packets]\n", argv[0]);
        return 0;
    }

    // Find available network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    printf("\nHere is a list of available devices on your system:\n\n");
    
    // Print a list of available network devices
    for (d = alldevs; d; d = d->next) {
        printf("Device name: %s\n", d->name);
        if (d->description) {
            printf("Device description: %s\n", d->description);
        } else {
            printf(" (Sorry, No description available for this device)\n");
        }
        printf("Flags: %d\n", d->flags);
    }

    printf("\nEnter the interface name on which you want to run the packet sniffer : ");
    
    fgets(dev_buff, sizeof(dev_buff) - 1, stdin);
    dev_buff[strlen(dev_buff) - 1] = '\0';

    if (strlen(dev_buff)) {
        dev = dev_buff;
        printf("\n ---You opted for device [%s] to capture [%d] packets---\n\n Starting capture...", dev, atoi(argv[2]));
    } else {
        printf("\nInvalid device name entered.\n");
        return -1;
    }

    // Open the selected network device for packet capture
    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    // Compile and set a packet filter
    if (pcap_compile(descr, &fp, argv[1], 0, pNet)) {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    // Begin packet capture loop, calling the callback function for each captured packet
    pcap_loop(descr, -1, callback, NULL);

    printf("\nDone with packet sniffing!\n");
    return 0;
}