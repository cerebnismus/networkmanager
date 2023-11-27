#ifndef PACKETS_HPP
#define PACKETS_HPP

// #pragma once  // it means only include once but,
// it's not officially part of the C/C++ standarts.
// TODO: what are pragma features in C/C++ ?

#include <ifaddrs.h>        /* getifaddrs from ifname */
// #include <netinet/in.h>
// #include <netinet/ip.h>
#include <net/if.h>
#include <net/bpf.h>        /* Berkeley Packet Filter */
#include <arpa/inet.h>

#include <sys/types.h>      /* XXX temporary hack to get u_ types */

#include <unistd.h>
#include <iostream>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>


/*  * --------------------
    * ETHERNET STRUCTURES
    * -------------------- */
/* The number of bytes in an ethernet (MAC) address. */
#define ETHER_ADDR_LEN        6

/* The number of bytes in the type field. */
#define ETHER_TYPE_LEN        2

/* The number of bytes in the trailing CRC field. */
#define ETHER_CRC_LEN        4

/* The length of the combined header. */
#define ETHER_HDR_LEN        (ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)

/* The minimum packet length. */
#define ETHER_MIN_LEN        64

/* The maximum packet length. */
#define ETHER_MAX_LEN       1518

/*
 * Mbuf adjust factor to force 32-bit alignment of IP header.
 * Drivers should do m_adj(m, ETHER_ALIGN) when setting up a
 * receive so the upper layers get the IP header properly aligned
 * past the 14-byte Ethernet header.
 */
#define ETHER_ALIGN             2       /* driver adjust for IP hdr alignment */

/* A macro to validate a length with */
#define ETHER_IS_VALID_LEN(foo)    \
    ((foo) >= ETHER_MIN_LEN && (foo) <= ETHER_MAX_LEN)

/* Structure of a 10Mb/s Ethernet header. */
typedef struct  ether_header {
    u_char  ether_dhost[ETHER_ADDR_LEN];
    u_char  ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
} ether_header_t;

/* Structure of a 48-bit Ethernet address. */
struct  ether_addr {
    u_char octet[ETHER_ADDR_LEN];
};

#define ether_addr_octet octet
#define ETHERTYPE_PUP           0x0200          /* PUP protocol */
#define ETHERTYPE_IP            0x0800          /* IP protocol */
#define ETHERTYPE_ARP           0x0806          /* Addr. resolution protocol */
#define ETHERTYPE_REVARP        0x8035          /* reverse Addr. resolution protocol */
#define ETHERTYPE_VLAN          0x8100          /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPV6          0x86dd          /* IPv6 */
#define ETHERTYPE_PAE           0x888e          /* EAPOL Port Access Entity IEEE 802.1X */
#define ETHERTYPE_RSN_PREAUTH   0x88c7          /* 802.11i RSN preauthentication */
#define ETHERTYPE_LOOPBACK      0x9000          /* used to test interfaces */
/* xxx - add more usefull types here */

#define ETHERTYPE_TRAIL         0x1000          /* Trailer packet */
#define ETHERTYPE_NTRAILER      16              /* Max # trailers */
#define ETHERMTU    (ETHER_MAX_LEN-ETHER_HDR_LEN-ETHER_CRC_LEN)
#define ETHERMIN    (ETHER_MIN_LEN-ETHER_HDR_LEN-ETHER_CRC_LEN)


#ifdef KERNEL_PRIVATE
/* The following are used by ethernet interfaces */
struct ether_addr *ether_aton(const char *);

#ifdef __APPLE__ || __FreeBSD__ || __OpenBSD__ 

    #ifdef BSD_KERNEL_PRIVATE
    extern u_char    etherbroadcastaddr[ETHER_ADDR_LEN];

    static __inline__ int
    _ether_cmp(const void * a, const void * b)
    {
        const u_int16_t * a_s = (const u_int16_t *)a;
        const u_int16_t * b_s = (const u_int16_t *)b;
        
        if (a_s[0] != b_s[0]
            || a_s[1] != b_s[1]
            || a_s[2] != b_s[2]) {
            return (1);
        }
        return (0);
    }

    #endif /* BSD_KERNEL_PRIVATE */

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__  */

#ifdef __linux__

#endif /* __linux__ */
// TODO : add more OS support

#define ETHER_IS_MULTICAST(addr) (*(addr) & 0x01) /* is address mcast/bcast? */

#endif /* KERNEL_PRIVATE */


/*  * ------------
    * IPv4 SECTION
    * ------------ */
#define IPVERSION               4

#define IPPROTO_ICMP            1               /* control message protocol */
#define IPPROTO_TCP             6               /* tcp */
#define IPPROTO_UDP             17              /* user datagram protocol */
// #define IPPROTO_IPIP         4               /* IPIP tunnels (older KA9Q tunnels use 94) */
#define IPPROTO_IPV4            4               /* IPv4 encapsulation */
#define IPPROTO_IPV6            41              /* IPv6-in-IPv4 tunnelling */
#define IPPROTO_ROUTING         43              /* IPv6 routing header */
#define IPPROTO_FRAGMENT        44              /* IPv6 fragmentation header */
#define IPPROTO_ICMPV6          58              /* ICMPv6 */
#define IPPROTO_RAW             255             /* raw IP packet */
#define IPPROTO_MAX             256             /* maximum protocol number */

/* Structure of an internet header, naked of options. */
typedef struct ipv4_header
{
#ifdef _IP_VHL
    u_char  ip_vhl;         /* version << 4 | header length >> 2 */
#else
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int   ip_hl:4,        /* header length */
            ip_v:4;         /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int   ip_v:4,         /* version */
            ip_hl:4;        /* header length */
#endif
#endif /* not _IP_VHL */
    u_char  ip_tos;          /* type of service */
    u_short ip_len;          /* total length */
    u_short ip_id;           /* identification */
    u_short ip_off;          /* fragment offset field */
#define IP_RF 0x8000         /* reserved fragment flag */
#define IP_DF 0x4000         /* dont fragment flag */
#define IP_MF 0x2000 next    /* more fragments flag */
#define IP_OFFMASK 0x1fff    /* mask for fragmenting bits */
    u_char  ip_ttl;          /* time to live */
    u_char  ip_p;            /* protocol */
    u_short ip_sum;          /* checksum */
    struct  in_addr ip_src;  /* source address */
    struct  in_addr ip_dst;  /* dest address */
} ipv4_header_t;

#ifdef _IP_VHL                                  /* ip_vhl is not in host byte order */
#define IP_MAKE_VHL(v, hl)  ((v) << 4 | (hl))   /* make a u_char ip_vhl */
#define IP_VHL_HL(vhl)      ((vhl) & 0x0f)      /* get u_char header length */
#define IP_VHL_V(vhl)       ((vhl) >> 4)        /* get u_char version */
#define IP_VHL_BORING       0x45                /* boring header == 01000101 */
#endif /* _IP_VHL */

#define IP_MAXPACKET        65535   /* maximum packet size */
/* Definitions for IP type of service (ip_tos) these will be deprecated soon. */
#define IPTOS_LOWDELAY      0x10    /* minimize delay */
#define IPTOS_THROUGHPUT    0x08    /* maximize throughput */
#define IPTOS_RELIABILITY   0x04    /* maximize reliability */
#define IPTOS_MINCOST       0x02    /* minimize cost */
#if 1
/* ECN RFC3168 obsoletes RFC2481, and these will be deprecated soon. */
#define IPTOS_CE                   0x01   /* congestion experienced */
#define IPTOS_ECT                  0x02   /* ECN-capable transport */
#endif /* 1 */

/*
 * ECN (Explicit Congestion Notification) codepoints in RFC3168
 * mapped to the lower 2 bits of the TOS field.
 */
#define IPTOS_ECN_NOTECT            0x00    /* not-ECT */
#define IPTOS_ECN_ECT1              0x01    /* ECN-capable transport (1) */
#define IPTOS_ECN_ECT0              0x02    /* ECN-capable transport (0) */
#define IPTOS_ECN_CE                0x03    /* congestion experienced */
#define IPTOS_ECN_MASK              0x03    /* ECN field mask */

/* Definitions for IP precedence (also in ip_tos) (hopefully unused) */
#define IPTOS_PREC_NETCONTROL       0xe0    /* network control */
#define IPTOS_PREC_INTERNETCONTROL  0xc0    /* internetwork control */
#define IPTOS_PREC_CRITIC_ECP       0xa0    /* critical/eCP */
#define IPTOS_PREC_FLASHOVERRIDE    0x80    /* flash override */
#define IPTOS_PREC_FLASH            0x60    /* flash */
#define IPTOS_PREC_IMMEDIATE        0x40    /* immediate */
#define IPTOS_PREC_PRIORITY         0x20    /* priority */
#define IPTOS_PREC_ROUTINE          0x00    /* routine */

#ifdef PRIVATE
/*
 * Definitions of traffic class for use within WIRELESS LAN. 
 * Mainly used by AFP for backup. Not recommended for general use.
 */
#define IP_TCLASS_BE                0x00    /* standard, best effort */
#define IP_TCLASS_BK                0x20    /* Background, low priority */
#define IP_TCLASS_VI                0x80    /* Interactive */
#define IP_TCLASS_VO                0xc0    /* Signalling */
#endif

/* Definitions for options. */
#define IPOPT_COPIED(o)           ((o)&0x80)  /* copied flag */
#define IPOPT_CLASS(o)            ((o)&0x60)  /* option class */
#define IPOPT_NUMBER(o)           ((o)&0x1f)  /* option number */

#define IPOPT_CONTROL             0x00        /* control */
#define IPOPT_RESERVED1           0x20        /* reserved */
#define IPOPT_DEBMEAS             0x40        /* debugging and measurement */
#define IPOPT_RESERVED2           0x60        /* reserved */

#define IPOPT_EOL                 0           /* end of option list */
#define IPOPT_NOP                 1           /* no operation */

#define IPOPT_RR                  7           /* record packet route */
#define IPOPT_TS                  68          /* timestamp */
#define IPOPT_SECURITY            130         /* provide s,c,h,tcc */
#define IPOPT_LSRR                131         /* loose source route */
#define IPOPT_SATID               136         /* satnet id */
#define IPOPT_SSRR                137         /* strict source route */
#define IPOPT_RA                  148         /* router alert */

/* Offsets to fields in options other than EOL and NOP. */
#define IPOPT_OPTVAL              0           /* option ID */
#define IPOPT_OLEN                1           /* option length */
#define IPOPT_OFFSET              2           /* offset within option */
#define IPOPT_MINOFF              4           /* min value of above */

/* Time stamp option structure. */
struct  ip_timestamp {
    u_char  ipt_code;               /* IPOPT_TS */
    u_char  ipt_len;                /* size of structure (variable) */
    u_char  ipt_ptr;                /* index of current entry */
#if BYTE_ORDER == LITTLE_ENDIAN
    u_char  ipt_oflw:4,             /* overflow counter */
            ipt_flg:4;              /* flags, see below */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_char  ipt_flg:4,              /* flags, see below */
            ipt_oflw:4;             /* overflow counter */
#endif
    union ipt_timestamp {
        u_long  ipt_time[1];
        struct  ipt_ta {
            struct in_addr ipt_addr;
            u_long ipt_time;
        } ipt_ta[1];
    } ipt_timestamp;
};

/* Flag bits for ipt_flg. */
#define IPTIMESTAMP_TSONLY        0       /* timestamps only */
#define IPTIMESTAMP_TSANDADDR     1       /* timestamps and addresses */
#define IPTIMESTAMP_PRESPEC       2       /* specified modules only */

/* bits for security (not byte swapped) */
#define IPOPT_SECUR_UNCLASS       0x0000
#define IPOPT_SECUR_CONFID        0xf135
#define IPOPT_SECUR_EFTO          0x789a
#define IPOPT_SECUR_MMMM          0xbc4d
#define IPOPT_SECUR_RESTR         0xaf13
#define IPOPT_SECUR_SECRET        0xd788
#define IPOPT_SECUR_TOPSECRET     0x6bc5

/* Security option structure. */
struct  ip_security {
    u_char  ips_code;               /* IPOPT_SECURITY */
    u_char  ips_len;                /* size of structure (variable) */
    u_char  ips_slen;               /* length of following data */
    u_char  ips_sec[3];             /* security compartment */
    u_char  ips_flag;               /* see below */
    u_char  ips_handle[40];         /* handle */
    u_char  ips_pub[1];             /* public data */
};

/* Flag bit definitions for ips_flag. */
#define IPS_DEFAULT     0x00        /* DEFAULT */
#define IPS_PRIMARY     0x01        /* PRIMARY */
#define IPS_EXPERIMENT  0x02        /* EXPERIMENTAL */
#define IPS_CONTROL     0x03        /* CONTROL */
#define IPS_INTEGRITY   0x05        /* INTEGRITY */
#define IPS_CONFIDENT   0x06        /* CONFIDENTIALITY */
#define IPS_KEY         0x07        /* KEY MANAGEMENT */
#define IPS_NETCONTROL  0x04        /* NETWORK CONTROL */

/* Record route option structure. */
struct  ip_rr {
    u_char  ipr_code;               /* IPOPT_RR */
    u_char  ipr_len;                /* size of structure (variable) */
    u_char  ipr_ptr;                /* index of current entry */
    u_char  ipr_numaddr;            /* number of addresses */
    struct  in_addr ipr_addr[1];    /* list of IP addrs */
};

/* Loose source route option structure. */
struct  ip_lsrr {
    u_char  ipl_code;               /* IPOPT_LSRR */
    u_char  ipl_len;                /* size of structure (variable) */
    u_char  ipl_ptr;                /* index of current entry */
    u_char  ipl_numaddr;            /* number of addresses */
    struct  in_addr ipl_addr[1];    /* list of IP addrs */
};

/* Strict source route option structure. */
struct  ip_ssrr {
    u_char  ipr_code;               /* IPOPT_SSRR */
    u_char  ipr_len;                /* size of structure (variable) */
    u_char  ipr_ptr;                /* index of current entry */
    u_char  ipr_numaddr;            /* number of addresses */
    struct  in_addr ipr_addr[1];    /* list of IP addrs */
};

/* Router alert option structure. */
struct  ip_ra {
    u_char  ipra_code;              /* IPOPT_RA */
    u_char  ipra_len;               /* size of structure (variable) */
    u_char  ipra_ptr;               /* index of current entry */
    u_char  ipra_num;               /* number of routers */
    u_int   ipra_lifetime;          /* lifetime of route */
    struct  in_addr ipra_addr[1];   /* list of router IP addrs */
};

/* Internet implementation parameters. */
struct  ip_param {
    u_int   ip_param_bits;          /* IP header bits */
    u_int   ip_param_mtu;           /* MTU in bytes */
};

/* Internet implementation parameters. */
#define MAXTTL      255     /* maximum time to live (seconds) */
#define IPDEFTTL    64      /* default ttl, from RFC 1340 */
#define IPFRAGTTL   30      /* time to live for frags (seconds) */
#define IPTTLDEC    1       /* subtracted when forwarding */
#define IP_MSS      576     /* default maximum segment size */


/*  * -------------
    * ICMP SECTION
    * ------------- */
/* Internal of an ICMP Router Advertisement */
struct icmp_ra_addr {
    u_int32_t ira_addr;
    u_int32_t ira_preference;
};

/* Structure of an icmp header. */
typedef struct icmp_header
{
    u_int8_t  icmp_type;    /* type of message, see below */
    u_int8_t  icmp_code;    /* type sub code */
    u_int16_t icmp_cksum;   /* ones complement checksum of struct */
    union
    {
        u_char ih_pptr;             /* ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;   /* ICMP_REDIRECT */

        struct ih_idseq             /* echo datagram */
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
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
    union
    {
        struct id_ts
        {
            u_int32_t its_otime;
            u_int32_t its_rtime;
            u_int32_t its_ttime;
        } id_ts;
        struct id_ip
        {
            ipv4_header_t idi_ip;
            /* options and then 64 bits of data */
        } id_ip;
        struct icmp_ra_addr id_radv;
            u_int32_t       id_mask;
            u_int8_t        id_data[1]; // char id_data[1];
    } icmp_dun;
#define icmp_otime  icmp_dun.id_ts.its_otime
#define icmp_rtime  icmp_dun.id_ts.its_rtime
#define icmp_ttime  icmp_dun.id_ts.its_ttime
#define icmp_ip     icmp_dun.id_ip.idi_ip
#define icmp_radv   icmp_dun.id_radv
#define icmp_mask   icmp_dun.id_mask
#define icmp_data   icmp_dun.id_data
} icmp_header_t;

/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enough to contain the returned ip header.
 * Only then can we do the check to see if 64 bits of packet
 * data have been returned, since we need to check the returned
 * ip header length.
 */
#define ICMP_MINLEN    8                /* abs minimum */
#define ICMP_TSLEN    (8 + 3 * sizeof (n_time))    /* timestamp */
#define ICMP_MASKLEN    12                /* address mask */
#define ICMP_ADVLENMIN    (8 + sizeof (struct ip) + 8)    /* min */
#ifndef _IP_VHL
#define ICMP_ADVLEN(p)    (8 + ((p)->icmp_ip.ip_hl << 2) + 8)
/* N.B.: must separately check that ip_hl >= 5 */
#else
#define ICMP_ADVLEN(p)    (8 + (IP_VHL_HL((p)->icmp_ip.ip_vhl) << 2) + 8)
/* N.B.: must separately check that header length >= 5 */
#endif

// !!!!!!!!!!!   THESE PARAMETERS MUST BE REFACTORED     !!!!!!!!!!!!!!!!   // 
/* Definition of type and code field values. */
#define  ICMP_ECHOREPLY                  0         /* echo reply */
#define  ICMP_UNREACH                    3         /* dest unreachable, codes: */
#define  ICMP_UNREACH_NET                0         /* bad net */
#define  ICMP_UNREACH_HOST               1         /* bad host */
#define  ICMP_UNREACH_PROTOCOL           2         /* bad protocol */
#define  ICMP_UNREACH_PORT               3         /* bad port */
#define  ICMP_UNREACH_NEEDFRAG           4         /* IP_DF caused drop */
#define  ICMP_UNREACH_SRCFAIL            5         /* src route failed */
#define  ICMP_UNREACH_NET_UNKNOWN        6         /* unknown net */
#define  ICMP_UNREACH_HOST_UNKNOWN       7         /* unknown host */
#define  ICMP_UNREACH_ISOLATED           8         /* src host isolated */
#define  ICMP_UNREACH_NET_PROHIB         9         /* prohibited access */
#define  ICMP_UNREACH_HOST_PROHIB        10        /* ditto */
#define  ICMP_UNREACH_TOSNET             11        /* bad tos for net */
#define  ICMP_UNREACH_TOSHOST            12        /* bad tos for host */
#define  ICMP_UNREACH_FILTER_PROHIB      13        /* admin prohib */
#define  ICMP_UNREACH_HOST_PRECEDENCE    14        /* host prec vio. */
#define  ICMP_UNREACH_PRECEDENCE_CUTOFF  15        /* prec cutoff */
#define  ICMP_SOURCEQUENCH               4         /* packet lost, slow down */
#define  ICMP_REDIRECT                   5         /* shorter route, codes: */
#define  ICMP_REDIRECT_NET               0         /* for network */
#define  ICMP_REDIRECT_HOST              1         /* for host */
#define  ICMP_REDIRECT_TOSNET            2         /* for tos and net */
#define  ICMP_REDIRECT_TOSHOST           3         /* for tos and host */
#define  ICMP_ECHO                       8         /* echo service */
#define  ICMP_ROUTERADVERT               9         /* router advertisement */
#define  ICMP_ROUTERSOLICIT              10        /* router solicitation */
#define  ICMP_TIMXCEED                   11        /* time exceeded, code: */
#define  ICMP_TIMXCEED_INTRANS           0         /* ttl==0 in transit */
#define  ICMP_TIMXCEED_REASS             1         /* ttl==0 in reass */
#define  ICMP_PARAMPROB                  12        /* ip header bad */
#define  ICMP_PARAMPROB_ERRATPTR         0         /* error at param ptr */
#define  ICMP_PARAMPROB_OPTABSENT        1         /* req. opt. absent */
#define  ICMP_PARAMPROB_LENGTH           2         /* bad length */
#define  ICMP_TSTAMP                     13        /* timestamp request */
#define  ICMP_TSTAMPREPLY                14        /* timestamp reply */
#define  ICMP_IREQ                       15        /* information request */
#define  ICMP_IREQREPLY                  16        /* information reply */
#define  ICMP_MASKREQ                    17        /* address mask request */
#define  ICMP_MASKREPLY                  18        /* address mask reply */
#define  ICMP_MAXTYPE                    18        /* maximum type code */

#define ICMP_INFOTYPE(type) \
    ((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO || \
    (type) == ICMP_ROUTERADVERT || (type) == ICMP_ROUTERSOLICIT || \
    (type) == ICMP_TSTAMP || (type) == ICMP_TSTAMPREPLY || \
    (type) == ICMP_IREQ || (type) == ICMP_IREQREPLY || \
    (type) == ICMP_MASKREQ || (type) == ICMP_MASKREPLY)

#ifdef KERNEL
void    icmp_error __P((struct mbuf *, int, int, n_long, struct ifnet *));
void    icmp_input __P((struct mbuf *, int));
#endif

#endif


/*  * ----------------
    * PACKETS CLASS
    * ---------------- */
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

// #endif // PACKETS_HPP