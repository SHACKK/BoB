#include "my_class.h"

Mac receive_arp_reply(char* dev, Ip sender_ip) {
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

        if ((ntohs(eth_hdr->type_) == 2054) && (ntohs(arp_hdr->sip_) == sender_ip) && (ntohs(arp_hdr->op_) == 2)){
            return arp_hdr->smac_;
        }

    }
    pcap_close(handle);
}

bool wait_arp_request(char* dev, Ip sender_ip) {
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

        if ((ntohs(eth_hdr->type_) == 2054) && (ntohs(arp_hdr->sip_) == sender_ip) && (ntohs(arp_hdr->op_) == 1)){
            return true;
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

    static unsigned char mac_address[6];

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
