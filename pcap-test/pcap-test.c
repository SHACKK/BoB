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

        struct libnet_ethernet_hdr* eth_header = (struct libnet_ethernet_hdr*)(packet);
        struct libnet_ipv4_hdr* ipv4_header = (struct libnet_ipv4_hdr*) (packet+14);
        //IPv4의 헤더값이 가변적이라 헤더길이 필드의 값을 알아야 하기 때문에 TCP헤더의 구조체는 if문 안에서 선언 : line 56

        if (ntohs(eth_header->ether_type)==2048) { //이더넷 Type 0248 = 0x0800 (ipv4)
            if (ipv4_header->ip_p==6) { //ip protocol = 6 (TCP)

                struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(packet+14+(ipv4_header->ip_hl));

                //TCP Port 128 = 0x80
                if (ntohs(tcp_header->th_dport)==128) {

                    printf("-----------------------------------\n");
                    printf("|%u bytes of HTTP Packets captured|\n", header->caplen);
                    printf("-----------------------------------\n");

                    //eth_header->ether_s(d)host는 배열이기 때문에 인자를 for문을 통해서 출력한다.
                    printf("<Source MAC>\n");
                    for(int i = 6 ; i > 0 ; i--) {
                        if (i!=1)
                            printf("%02x : ", eth_header->ether_shost[i]);
                        else printf("%02x\n", eth_header->ether_shost[i]);
                    }
                    printf("<Destination MAC>\n");
                    for(int i = 6 ; i > 0 ; i--) {
                        if (i!=1)
                            printf("%02x : ", eth_header->ether_dhost[i]);
                        else printf("%02x\n", eth_header->ether_dhost[i]);
                    }

                    //inet_ntoa()함수를 사용하기위해 ipv4_header->ip_src(dst).s_addr의 값을 parameter의 자료형인 structure로 만들어줌
                    struct in_addr ip_src_add = {(ipv4_header->ip_src.s_addr)};
                    struct in_addr ip_dst_add= {(ipv4_header->ip_dst.s_addr)};

                    //inet_ntoa()는 .까지 찍은 형태의 char[]로 반환해준다.
                    printf("\n<Source IP Address>\n%s\n", inet_ntoa(ip_src_add));
                    printf("<Destination IP Address>\n%s\n\n", inet_ntoa(ip_dst_add));

                    //TCP Souce, Destination Port 필드는 각각 2바이트이므로 ntohs() 사용
                    printf("<Source Port>\n%d\n", ntohs(tcp_header->th_sport));
                    printf("<Destination Port>\n%d\n\n", ntohs(tcp_header->th_dport));

                    printf("<HTTP Packet Starts with>\n");
                    for(int i=0; i<8; i++) {
                        //Ethernet, IPv4, TCP 헤더의 길이를 모두 더한 값의 주소부터는 HTTP 데이터
                        printf(" %02x", *(packet+14+((ipv4_header->ip_hl))+((tcp_header->th_off))+i));
                    }
                    printf("\n\n");

                }

            }

        }

	}
	pcap_close(pcap);
}
