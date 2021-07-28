#pragma once

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

Mac receive_arp_packet(char* dev);

unsigned char* getmac();

char* getip(char* dev);
