#pragma once

#include <cstdint>

#pragma pack(push, 1)
struct TcpHdr
{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t reserve:4;
    uint16_t HLEN:4;
    uint16_t flag:8;
    uint16_t win_size;
    uint16_t cheksum;
    uint16_t urgent_pointer;
};
#pragma pack(pop)
