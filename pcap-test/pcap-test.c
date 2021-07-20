#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "libnet/include/libnet.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char *argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
		}
		printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr* eth_header = (struct libnet_ethernet_hdr*)(packet);
        struct libnet_ipv4_hdr* ipv4_header = (struct libnet_ipv4_hdr*)(packet+14);

        if (eth_header->ether_type==2048) {
            if (ipv4_header->ip_p==6) {     //sum this two line!!
                struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(packet+14+(ipv4_header->ip_hl));
                if (tcp_header->th_dport==80) {

                    printf("Destination port is : %x\n", *(eth_header->ether_dhost));
                    printf("Source MAC is : %x\n", *(eth_header->ether_shost));

                    printf("Source IP Address : %d\n", (ipv4_header->ip_src));
                    printf("Destination IP Address : %d\n", (ipv4_header->ip_dst));

                    printf("Source Port : %d\n", (tcp_header->th_sport));
                    printf("Destination Port : %d\n", (tcp_header->th_dport));

                    printf("HTTP Packet Starts with :");
                    for(int i=0; i<8; i++) {
                        printf("\t%02x", packet+14+(ipv4_header->ip_hl)+(tcp_header->th_off)+i);
                    }
                }

            }

        }

	}
	pcap_close(pcap);
}
