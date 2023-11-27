#include "packets.hpp"

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


// NOT USING
// generic checksum calculation algorithm
unsigned short 
cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

    if (nleft == 1)
    {
      *(unsigned char *)(&answer) = *(unsigned char *)w;
      sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}



void 
printReceivedPackets(const ether_header_t& ethHeader, const ipv4_header_t& ipHeader, const icmp_header_t& icmpHeader) 
{
    std::cout << std::endl << "----------------------------------" << std::endl;
    std::cout << "Destination MAC: ";
    for (int i = 0; i < 6; ++i) 
    {
        std::cout << std::hex << static_cast<int>(ethHeader.ether_dhost[i]) << std::dec;
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl << "Source MAC: ";
    for (int i = 0; i < 6; ++i) 
    {
        std::cout << std::hex << static_cast<int>(ethHeader.ether_shost[i]) << std::dec;
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl << "Ethernet Type: 0x" << std::hex << ntohs(ethHeader.ether_type) << std::dec << std::endl;

    char source_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader.ip_src), source_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader.ip_dst), dest_ip_str, INET_ADDRSTRLEN);
    std::cout << "----------------------------------" << std::endl;
    std::cout << "Version: 0x" << std::hex << static_cast<int>(ipHeader.ip_v) << std::dec << std::endl;
    std::cout << "Header Length: 0x" << std::hex << static_cast<int>(ipHeader.ip_hl) << std::dec << std::endl;
    std::cout << "Type of Service (TOS): 0x" << std::hex << static_cast<int>(ipHeader.ip_tos) << std::dec << std::endl;
    std::cout << "Total Length: " << ntohs(ipHeader.ip_len) << std::endl;
    std::cout << "ID: " << ntohs(ipHeader.ip_id) << std::endl;
    std::cout << "Fragment Offset: " << ntohs(ipHeader.ip_off) << std::endl;
    std::cout << "TTL: " << static_cast<int>(ipHeader.ip_ttl) << std::endl;
    std::cout << "Protocol: " << static_cast<int>(ipHeader.ip_p) << std::endl;
    std::cout << "Checksum: 0x" << std::hex << ntohs(ipHeader.ip_sum) << std::dec << std::endl;
    std::cout << "Source IP: " << source_ip_str << std::endl;
    std::cout << "Destination IP: " << dest_ip_str << std::endl;
    std::cout << "----------------------------------" << std::endl;
    std::cout << "ICMP Type: " << static_cast<int>(icmpHeader.icmp_type) << std::endl;
    std::cout << "ICMP Code: " << static_cast<int>(icmpHeader.icmp_code) << std::endl;
    std::cout << "ICMP Checksum: 0x" << std::hex << ntohs(icmpHeader.icmp_cksum) << std::dec << std::endl;
    std::cout << "ICMP Identifier: " << ntohs(icmpHeader.icmp_id) << std::endl;
    std::cout << "ICMP Sequence: " << ntohs(icmpHeader.icmp_seq) << std::endl;
    std::cout << "----------------------------------" << std::endl;
}


int 
packets::init_bpf(int bpfNumber, const char *interface)
{
    std::string buff;
    struct ifreq boundif;

    buff = "/dev/bpf";
    buff += std::to_string(bpfNumber);

    this->sockFd = open(buff.c_str(), O_RDWR);
    if (this->sockFd == -1) {
        perror("open: Socket create error");
        exit(1);
    }

    strcpy(boundif.ifr_name, interface);
    if (ioctl(this->sockFd, BIOCSETIF, &boundif) == -1) {
        perror("ioctl: BIOCSETIF error");
        close(this->sockFd);
        exit(1);
    }

    this->buffLen = 1;
    if (ioctl(this->sockFd, BIOCIMMEDIATE, &this->buffLen) == -1) {
        perror("ioctl: BIOCIMMADIATE error");
        close(this->sockFd);
        exit(1);
    }

    if (ioctl(this->sockFd, BIOCGBLEN, &this->buffLen)) {
        perror("ioctl: BIOCBLEN error");
        close(this->sockFd);
        exit(1);
    }

    this->bpfBuff = new struct bpf_hdr[this->buffLen];
    return (this->sockFd);
}


char 
*packets::receive_bpf()
{
    int readBytes;
    char *ptr;
    ether_header_t *ethhdr;
    ipv4_header_t *iphdr;
    icmp_header_t *icmphdr;

    while (1)
    {
        memset(this->bpfBuff, 0, this->buffLen);
        readBytes = read(this->sockFd, bpfBuff, this->buffLen);
        if (readBytes > 0)
        {
            ptr = reinterpret_cast<char *>(this->bpfBuff);
            while (ptr < (reinterpret_cast<char *>(this->bpfBuff) + readBytes))
            {
                this->bpfPacket = reinterpret_cast<bpf_hdr *>(ptr);
                ethhdr = (ether_header_t*)((char*) bpfPacket + bpfPacket->bh_hdrlen);
                iphdr = (ipv4_header_t *)((char*) ethhdr + sizeof(ether_header_t));
                icmphdr = (icmp_header_t *)((char*) iphdr + sizeof(ipv4_header_t));

                // Check if it's an ICMP packet
                if (iphdr->ip_p == IPPROTO_ICMP) 
                {
                    // Check if it's an ICMP echo request
                    if (icmphdr->icmp_type == 8) {
                        std::cout << std::endl << " * receive_bpf: echo request";
                        printReceivedPackets(*ethhdr, *iphdr, *icmphdr);
                    }
                    // Check if it's an ICMP echo reply
                    if (icmphdr->icmp_type == 0) {
                        std::cout << std::endl << "** receive_bpf: echo reply";
                        printReceivedPackets(*ethhdr, *iphdr, *icmphdr);
                    }
                }
                ptr += BPF_WORDALIGN(bpfPacket->bh_hdrlen + bpfPacket->bh_caplen);
            }
        }
    }
    delete[] this->bpfBuff;
    close(this->sockFd);
    return (NULL);
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
packets::craft_ipv4_header(char *packet, const char *interface, const char *dest_ip, int ttl)
{

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

    // craft ipv4 header
    // ipv4_header_t *ip_hdr = (ipv4_header_t *)packet;

    // char packet[sizeof(ipv4_header_t) + sizeof(icmp_header_t)];
    // memset(packet, 0, sizeof(packet));

    ipv4_header_t ip_hdr;
    ip_hdr.ip_hl = 5;
    ip_hdr.ip_v = 4;
    ip_hdr.ip_tos = 0;
    ip_hdr.ip_len = sizeof(ipv4_header_t) + sizeof(icmp_header_t);
    ip_hdr.ip_id = 0;
    ip_hdr.ip_off = 0;
    ip_hdr.ip_ttl = ttl;
    ip_hdr.ip_p = IPPROTO_RAW;
    ip_hdr.ip_sum = 0;
    ip_hdr.ip_src.s_addr = inet_addr(ipAddr);
    ip_hdr.ip_dst.s_addr = inet_addr(dest_ip);
    ip_hdr.ip_sum = calculate_checksum(&ip_hdr, sizeof(ip_hdr));

    // !!!!! TODO CRAFT PACKET !!!!!!!!!!
    freeifaddrs(ifaddr);
}


void 
packets::send_sock(const char *interface, const char *dest_ip)
{
    int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket: Could not create socket");
        exit(1);
    }

    int option_value = 1; // Set SO_DEBUG option Enable debugging
    if (setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &option_value, sizeof(option_value)) < 0) {
        perror("setsockopt: Could not set SO_DEBUG option");
        close(sockfd);
        exit(1);
    }

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

    if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("sendto: Could not send packet");
        exit(1);
    }
    else {
        printf("\n --- packet sent to %s ---\n", dest_ip);
    }

    close(sockfd);
}