#include "packets.hpp"


void 
printReceivedPackets(const s_ehternet_header& ethHeader, const s_ipv4_header& ipHeader, const s_icmp_header& icmpHeader) 
{
    std::cout << std::endl << "----------------------------------" << std::endl;
    std::cout << "Destination MAC: ";
    for (int i = 0; i < 6; ++i) 
    {
        std::cout << std::hex << static_cast<int>(ethHeader.dest_mac[i]) << std::dec;
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl << "Source MAC: ";
    for (int i = 0; i < 6; ++i) 
    {
        std::cout << std::hex << static_cast<int>(ethHeader.source_mac[i]) << std::dec;
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl << "Ethernet Type: 0x" << std::hex << ntohs(ethHeader.ether_type) << std::dec << std::endl;

    char source_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader.source_ip), source_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader.dest_ip), dest_ip_str, INET_ADDRSTRLEN);
    std::cout << "----------------------------------" << std::endl;
    std::cout << "Version & IHL: 0x" << std::hex << static_cast<int>(ipHeader.version_ihl) << std::dec << std::endl;
    std::cout << "Type of Service (TOS): 0x" << std::hex << static_cast<int>(ipHeader.tos) << std::dec << std::endl;
    std::cout << "Total Length: " << ntohs(ipHeader.total_length) << std::endl;
    std::cout << "ID: " << ntohs(ipHeader.id) << std::endl;
    std::cout << "Fragment Offset: " << ntohs(ipHeader.fragment_offset) << std::endl;
    std::cout << "TTL: " << static_cast<int>(ipHeader.ttl) << std::endl;
    std::cout << "Protocol: " << static_cast<int>(ipHeader.protocol) << std::endl;
    std::cout << "Checksum: 0x" << std::hex << ntohs(ipHeader.checksum) << std::dec << std::endl;
    std::cout << "Source IP: " << source_ip_str << std::endl;
    std::cout << "Destination IP: " << dest_ip_str << std::endl;
    std::cout << "----------------------------------" << std::endl;
    std::cout << "ICMP Type: " << static_cast<int>(icmpHeader.icmp_type) << std::endl;
    std::cout << "ICMP Code: " << static_cast<int>(icmpHeader.icmp_code) << std::endl;
    std::cout << "ICMP Checksum: 0x" << std::hex << ntohs(icmpHeader.icmp_checksum) << std::dec << std::endl;
    std::cout << "ICMP Identifier: " << ntohs(icmpHeader.icmp_identifier) << std::endl;
    std::cout << "ICMP Sequence: " << ntohs(icmpHeader.icmp_sequence) << std::endl;
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
        perror("Socket Create Error = ");
        exit(1);
    }

    strcpy(boundif.ifr_name, interface);
    if (ioctl(this->sockFd, BIOCSETIF, &boundif) == -1) {
        perror("ioctl BIOCSETIF error = ");
        close(this->sockFd);
        exit(1);
    }

    this->buffLen = 1;
    if (ioctl(this->sockFd, BIOCIMMEDIATE, &this->buffLen) == -1) {
        perror("ioctl BIOCIMMADIATE error = ");
        close(this->sockFd);
        exit(1);
    }

    if (ioctl(this->sockFd, BIOCGBLEN, &this->buffLen)) {
        perror("ioctl BIOCBLEN error = ");
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
    s_ehternet_header *ethhdr;
    s_ipv4_header *iphdr;
    s_icmp_header *icmphdr;

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
                ethhdr = (s_ehternet_header*)((char*) bpfPacket + bpfPacket->bh_hdrlen);
                iphdr = (s_ipv4_header *)((char*) ethhdr + sizeof(s_ehternet_header));
                icmphdr = (s_icmp_header *)((char*) iphdr + sizeof(s_ipv4_header));

                // Check if it's an ICMP packet
                if (iphdr->protocol == IPPROTO_ICMP) 
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
    unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


void 
packets::send_sock(const char *dest_ip)
{
    int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Could not create socket");
        exit(1);
    }

    int option_value = 1; // Set SO_DEBUG option Enable debugging
    if (setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &option_value, sizeof(option_value)) < 0) {
        perror("Could not set SO_DEBUG option");
        close(sockfd);
        exit(1);
    }

    s_icmp_header icmp_hdr;
    struct sockaddr_in dest_addr;
    icmp_hdr.icmp_type = 8;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_identifier = getpid();
    icmp_hdr.icmp_sequence = 0;
    icmp_hdr.icmp_checksum = 0;
    icmp_hdr.icmp_checksum = calculate_checksum(&icmp_hdr, sizeof(icmp_hdr));

    s_ipv4_header ip_hdr;

    dest_addr.sin_family = PF_INET;
    inet_pton(PF_INET, dest_ip, &dest_addr.sin_addr);

    // Send the packet
    if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("Could not send packet");
        exit(1);
    }
    else {
        printf("\n --- packet sent to %s ---\n", dest_ip);
    }

    close(sockfd);
}