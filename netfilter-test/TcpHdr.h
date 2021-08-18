#pragma once

#include <cstdint>

#pragma pack(push, 1)
struct TcpHdr
{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t hlne_flag;
    uint16_t win_size;
    uint16_t cheksum;
    uint16_t urgent_pointer;
};
#pragma pack(pop)
