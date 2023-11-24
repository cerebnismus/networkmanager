#ifndef PACKETS_HPP
#define PACKETS_HPP

// #pragma once  // it means only include once but,
// it's not officially part of the C/C++ standarts.

#include <netinet/in.h>  // Internet Protocol family
#include <net/bpf.h>     // Berkeley Packet Filter
#include <iostream>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>


#ifdef __APPLE__

#endif

#ifdef __FreeBSD__

#endif

#ifdef __linux__

#endif




typedef struct s_icmp_header 
{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_checksum;
    uint16_t icmp_identifier;
    uint16_t icmp_sequence;
} s_icmp_header;


typedef struct s_ipv4_header
{
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    in_addr source_ip;
    in_addr dest_ip;
} s_ipv4_header;


typedef struct s_ehternet_header
{
    uint8_t dest_mac[6];
    uint8_t source_mac[6];
    uint16_t ether_type;
} s_ehternet_header;


class packets
{
    public:
        int sockFd;
        int buffLen;
        struct bpf_hdr  *bpfBuff;
        struct bpf_hdr  *bpfPacket;
        int init_bpf(int bpfNumber, const char *interface);
        void send_sock(const char *interface, const char *dest_ip);
        unsigned short calculate_checksum(void *b, int len);
        char *receive_bpf();
};

#endif // PACKETS_HPP