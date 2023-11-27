#include "packets.hpp"

// OLD version of dump function (!not using)
// dumps raw memory in hex byte and printable split format
void 
dump(const unsigned char *data_buffer, const unsigned int length)
{
    unsigned char byte;
    unsigned int i, j;
    for(i=0; i < length; i++) 
    {
        byte = data_buffer[i];
        fprintf(stdout, "%02x ", data_buffer[i]);  // display byte in hex
        if(((i%16)==15) || (i==length-1)) {
            for(j=0; j < 15-(i%16); j++)
                fprintf(stdout, "   ");
            fprintf(stdout, "| ");
            for(j=(i-(i%16)); j <= i; j++) {  // display printable bytes from line
                byte = data_buffer[j];
                if((byte > 31) && (byte < 127)) // outside printable char range
                    fprintf(stdout, "%c", byte);
                else
                    fprintf(stdout, ".");
            }
            fprintf(stdout, "\n"); // end of the dump line (each line 16 bytes)
        }
    }
}

// OLD version of checksum function (!not using)
// generic checksum calculation algorithm
unsigned short 
cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;
    while (nleft > 1) {
      sum += *w++;
      nleft -= 2;
    }
    if (nleft == 1) {
      *(unsigned char *)(&answer) = *(unsigned char *)w;
      sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
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
packets::craft_packet(char *packet, const char *interface, const char *dest_ip, int ttl)
{   // !!!!! TODO CRAFT PACKET !!!!!!!!!!

    // get local ip address from given interface name
    struct ifaddrs *ifaddr, *ifa;
    char *ipAddr = nullptr;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET && strcmp(ifa->ifa_name, interface) == 0) {
            ipAddr = new char[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ipAddr, INET_ADDRSTRLEN);
            break;
        }
    }

    ipv4_header_t ip_hdr;
    ip_hdr.ip_hl = 5;  // Header length
    ip_hdr.ip_v = 4;   // IPv4
    ip_hdr.ip_tos = 0; // Type of Service
    // ip_hdr.ip_len = sizeof(ipv4_header_t) + sizeof(icmp_header_t);
    ip_hdr.ip_len = htons(sizeof(ipv4_header_t) + sizeof(icmp_header_t)); // Total length
    ip_hdr.ip_id = htons(26); // Identification
    ip_hdr.ip_off = 0; // Fragment offset
    ip_hdr.ip_ttl = ttl;
    ip_hdr.ip_p = IPPROTO_ICMP; // IPPROTO_RAW
    ip_hdr.ip_sum = 0; // Checksum (calculated below)
    ip_hdr.ip_src.s_addr = inet_addr(ipAddr);
    ip_hdr.ip_dst.s_addr = inet_addr(dest_ip);

    // Calculate the checksum
    ip_hdr.ip_sum = calculate_checksum(&ip_hdr, sizeof(ip_hdr));

    // Copy the crafted header into the packet buffer
    memcpy(packet, &ip_hdr, sizeof(ipv4_header_t));



    icmp_header_t icmp_hdr;
    icmp_hdr.icmp_type = 8;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_cksum = 0;
    icmp_hdr.icmp_id = getpid();
    icmp_hdr.icmp_seq = 0;
    icmp_hdr.icmp_cksum = calculate_checksum(&icmp_hdr, sizeof(icmp_hdr));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = PF_INET;
    inet_pton(PF_INET, dest_ip, &dest_addr.sin_addr);

    if (sendto(sockFd, &icmp_hdr, sizeof(icmp_hdr), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("sendto: Could not send packet");
        exit(1);
    }
    else {
        printf("\n --- packet sent to %s ---\n", dest_ip);
    }


    freeifaddrs(ifaddr);
}


void 
packets::craft_socket(const char *interface, const char *dest_ip)
{
    this->sockFd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (this->sockFd < 0) {
        perror("socket: Could not create socket");
        exit(1);
    }

    int option_value = 1; // Set SO_DEBUG option Enable debugging
    if (setsockopt(this->sockFd, SOL_SOCKET, SO_DEBUG, &option_value, sizeof(option_value)) < 0) {
        perror("setsockopt: Could not set SO_DEBUG option");
        close(this->sockFd);
        exit(1);
    }


    // todo signal handler for ctrl c (SIGINT)
    close(this->sockFd);
}