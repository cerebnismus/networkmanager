#ifndef PACKETS_HPP
#define PACKETS_HPP

// #pragma once  // it means only include once but,
// it's not officially part of the C/C++ standarts.
// TODO: what are pragma features in C/C++ ?

#include <ifaddrs.h>      /* getifaddrs from ifname */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/bpf.h>       /* Berkeley Packet Filter */
#include <arpa/inet.h>

#include <sys/cdefs.h>
#include <sys/types.h>

#include <unistd.h>
#include <iostream>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#ifdef __APPLE__

#endif

#ifdef __FreeBSD__

#endif

#ifdef __linux__

#endif

#define IPPROTO_ICMP            1               /* control message protocol */
#define IPPROTO_TCP             6               /* tcp */
#define IPPROTO_UDP             17              /* user datagram protocol */

#define IPPROTO_IPIP            4               /* IPIP tunnels (older KA9Q tunnels use 94) */
#define IPPROTO_IPV4            4               /* IPv4 encapsulation */

#define IPPROTO_IPV6            41              /* IPv6-in-IPv4 tunnelling */
#define IPPROTO_ROUTING         43              /* IPv6 routing header */
#define IPPROTO_FRAGMENT        44              /* IPv6 fragmentation header */
#define IPPROTO_ICMPV6          58              /* ICMPv6 */

#define IPPROTO_RAW             255             /* raw IP packet */
#define IPPROTO_MAX             256


typedef struct icmp_header
{
    u_int8_t type;      /* message type */
    u_int8_t code;      /* type sub-code */
    u_int16_t checksum; /* one's complement checksum of struct */

    u_int8_t  icmp_type;	/* type of message, see below */
    u_int8_t  icmp_code;	/* type sub code */
    u_int16_t icmp_cksum;	/* ones complement checksum of struct */
    union
    {
        u_char ih_pptr;		/* ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;	/* gateway address */
        struct ih_idseq		/* echo datagram */
        {
            u_int16_t icd_id;
            u_int16_t icd_seq;
        } ih_idseq;
        u_int32_t ih_void;

        /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
        struct ih_pmtu
        {
            u_int16_t ipm_void;
            u_int16_t ipm_nextmtu;
        } ih_pmtu;

        struct ih_rtradv
        {
            u_int8_t irt_num_addrs;
            u_int8_t irt_wpa;
            u_int16_t irt_lifetime;
        } ih_rtradv;
    } icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
    union
    {
        struct
        {
            u_int32_t its_otime;
            u_int32_t its_rtime;
            u_int32_t its_ttime;
        } id_ts;
        struct
        {
            struct ip idi_ip;
            /* options and then 64 bits of data */
        } id_ip;
        struct icmp_ra_addr id_radv;
            u_int32_t   id_mask;
            u_int8_t    id_data[1];
    } icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_radv	icmp_dun.id_radv
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
} icmp_header_t;


typedef struct ipv4_header
{
#if BYTE_ORDER == LITTLE_ENDIAN 
    u_char  ip_hl : 4,       /* header length */
            ip_v  : 4;       /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
    u_char  ip_v  : 4,       /* version */
            ip_hl : 4;       /* header length */
#endif
    u_char  ip_tos;          /* type of service */
    short   ip_len;          /* total length */
    u_short ip_id;           /* identification */
    short   ip_off;          /* fragment offset field */
#define IP_DF 0x4000         /* dont fragment flag */
#define IP_MF 0x2000 next    /* more fragments flag */
    u_char  ip_ttl;          /* time to live */
    u_char  ip_p;            /* protocol */
    u_short ip_sum;          /* checksum */
    struct  in_addr ip_src;  /* source address */
    struct  in_addr ip_dst;  /* dest address */
} ipv4_header_t;


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
        void craft_ipv4_header(char *packet, const char *interface, const char *dest_ip, int ttl);
        unsigned short calculate_checksum(void *b, int len);
        char *receive_bpf();
};

#endif // PACKETS_HPP