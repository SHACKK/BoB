#include "Ip.h"

#pragma pack(push, 1)
struct IpHdr
{
    uint8_t IHL:4;
    uint8_t ver:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t offset:13;
    uint16_t flag:3;
    uint8_t ttl;
    uint8_t protcol;
    uint16_t checksum;
    Ip sip;
    Ip dip;
};
#pragma pack(pop)
