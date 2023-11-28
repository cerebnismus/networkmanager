#include "packets.hpp"

// todo constructor and destructor for packets class
// todo research and implement the following functions

/*
packets::packets() 
{
    bpf_sock_fd = -1;
    craft_sock_fd = -1;
}


packets::~packets() 
{
    if (bpf_sock_fd > 0) close(bpf_sock_fd);
    if (craft_sock_fd > 0) close(craft_sock_fd);
    freeifaddrs(ifaddr);    // Free the allocated memory
    delete[] ipAddr;        // Free the allocated memory
}

*/


#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

static unsigned short
in_cksum(const unsigned short *addr, int len, unsigned short csum)
{
	int nleft = len;
	const unsigned short *w = addr;
	unsigned short answer;
	int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += ODDBYTE(*(unsigned char *)w); /* le16toh() may be unavailable on old systems */

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}



unsigned short 
packets::calculate_checksum(void *b, int len) 
{  
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result; // TODO can be define in one line
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


void
packets::craft_packet(const char *interface, const char *dest_ip, int ttl)
{
    // get local ip address from given interface name
    struct ifaddrs *ifaddr, *ifa;
    char *ipAddr = nullptr;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET && strcmp(ifa->ifa_name, interface) == 0) 
        {
            ipAddr = new char[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ipAddr, INET_ADDRSTRLEN);
            break;
        }
    }

    // Craft the packet
    char crafted_packet[sizeof(ipv4_header_t) + sizeof(icmp_header_t)];
    memset(crafted_packet, 0, sizeof(ipv4_header_t) + sizeof(icmp_header_t));

    ipv4_header_t ip_hdr;
    ip_hdr.ip_hl = 5;  // Header length
    ip_hdr.ip_v = 4;   // IPv4
    ip_hdr.ip_tos = 0; // Type of Service
    ip_hdr.ip_len = sizeof(ipv4_header_t) + sizeof(icmp_header_t);
    // ip_hdr.ip_len = htons(sizeof(ipv4_header_t) + sizeof(icmp_header_t)); // Total length
    ip_hdr.ip_id = htons(54321); // Identification
    ip_hdr.ip_off = 0; // Fragment offset
    ip_hdr.ip_ttl = ttl; // Time to live
    ip_hdr.ip_p = IPPROTO_ICMP;
    ip_hdr.ip_sum = 0; // Checksum (calculated below)
    ip_hdr.ip_src.s_addr = inet_addr(ipAddr);
    ip_hdr.ip_dst.s_addr = inet_addr(dest_ip);

    ip_hdr.ip_sum = calculate_checksum(&ip_hdr, sizeof(ip_hdr));
    memcpy(crafted_packet, &ip_hdr, sizeof(ipv4_header_t));

    icmp_header_t icmp_hdr;
    icmp_hdr.icmp_type = ICMP_ECHO;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_cksum = 0;
    icmp_hdr.icmp_id = getpid();
    icmp_hdr.icmp_seq = 0; /* don't ++ here, it can be a macro */

    // get uint32_t timestamp
    uint32_t timestamp = htonl(time(NULL));
    memcpy(icmp_hdr.icmp_data, &timestamp, sizeof(timestamp));

    // cerebnismus //
    icmp_hdr.icmp_data[9] = 'c';
    icmp_hdr.icmp_data[10] = 'e';
    icmp_hdr.icmp_data[11] = 'r';
    icmp_hdr.icmp_data[12] = 'e';
    icmp_hdr.icmp_data[13] = 'b';
    icmp_hdr.icmp_data[14] = 'n';
    icmp_hdr.icmp_data[15] = 'i';
    icmp_hdr.icmp_data[16] = 's';
    icmp_hdr.icmp_data[17] = 'm';
    icmp_hdr.icmp_data[18] = 'u';
    icmp_hdr.icmp_data[19] = 's';

    icmp_hdr.icmp_cksum = calculate_checksum(&icmp_hdr, sizeof(icmp_hdr));
    memcpy(crafted_packet + sizeof(ipv4_header_t), &icmp_hdr, sizeof(icmp_header_t));


    struct sockaddr_in dest_addr;
    dest_addr.sin_family = PF_INET;
    inet_pton(PF_INET, dest_ip, &dest_addr.sin_addr);

    if (sendto(craft_sock_fd, crafted_packet, sizeof(crafted_packet), 0,
            (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("sendto: Could not send packet");
        close(craft_sock_fd);
        exit(1);
    }
    else {
        printf("\n --- packet sent to %s ---\n", dest_ip);
    }

    freeifaddrs(ifaddr);    // Free the allocated memory
    delete[] ipAddr;        // Free the allocated memory
    close(craft_sock_fd);
}


void 
packets::craft_socket(const char *interface, const char *dest_ip)
{
    craft_sock_fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (craft_sock_fd < 0) {
        perror("socket: Could not create socket");
        exit(1);
    }

    int hdrincl = 1;  // Indicate that the IP header is included in the packet
    if (setsockopt(craft_sock_fd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) < 0) {
        perror("setsockopt: Could not set IP_HDRINCL option");
        close(craft_sock_fd);
        exit(1);
    }

    int sodebug_option_value = 1; // Set SO_DEBUG option Enable debugging
    if (setsockopt(craft_sock_fd, SOL_SOCKET, SO_DEBUG, &sodebug_option_value, sizeof(sodebug_option_value)) < 0) {
        perror("setsockopt: Could not set SO_DEBUG option");
        close(craft_sock_fd);
        exit(1);
    }

    int sodebug_option_value_size = sizeof(sodebug_option_value);
    if (getsockopt(craft_sock_fd, SOL_SOCKET, SO_DEBUG, &sodebug_option_value, (socklen_t *)&sodebug_option_value_size) < 0) {
        perror("getsockopt: Could not get SO_DEBUG option");
        close(craft_sock_fd);
        exit(1);
    }
    printf(" - Socket created with SO_DEBUG option: %s\n", (sodebug_option_value ? "ON" : "OFF"));

    // todo craft packet logic where
    craft_packet(interface, dest_ip, IPDEFTTL-34);
}