#include "packets.hpp"


void 
packets::bpf_print(const ether_header_t& ethHeader, const ipv4_header_t& ipHeader, const icmp_header_t& icmpHeader) 
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
    time_t timestamp = ntohl(*(uint32_t *)icmpHeader.icmp_data);
    std::cout << "ICMP Timestamp: " << ctime(&timestamp);
    std::cout << "ICMP Data: " << icmpHeader.icmp_data + 8 << std::endl;
    std::cout << "----------------------------------" << std::endl;
}


int
packets::bpf_init(const char *interface)
{
    std::string buff;
    struct ifreq ifr;

    // Select BPF device for bound to the socket
    for(int i=0; i<256; i++)
    {
        buff = "/dev/bpf";
        buff += std::to_string(i);
        bpf_sock_fd = open(buff.c_str(), O_RDWR);
        if (bpf_sock_fd != -1) {
            std::cout << " - BPF device found: " << buff << std::endl;
            break;
        }
    }

    // biocsetif: set the interface to bound to the socket
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    if (ioctl(bpf_sock_fd, BIOCSETIF, &ifr) < 0) {
        perror("Error setting interface");
        return 1;
    }

    bpf_buff_len = 1; // biocpromisc: set the if to promiscuous mode
    if (ioctl(bpf_sock_fd, BIOCPROMISC, &bpf_buff_len) < 0) {
        perror("Error enabling promiscuous mode");
        return 1;
    }

    // bioimmediate: read packets as soon as they arrive
    if (ioctl(bpf_sock_fd, BIOCIMMEDIATE, &bpf_buff_len) < 0) {
        perror("ioctl: BIOCIMMADIATE error");
        close(bpf_sock_fd);
        exit(1);
    }

    // biocgblen: get the buffer length
    if (ioctl(bpf_sock_fd, BIOCGBLEN, &bpf_buff_len)) {
        perror("ioctl: BIOCBLEN error");
        close(bpf_sock_fd);
        exit(1);
    }

    // todo BIOCSBLEN, BIOCSHDRCMPLT, BIOCSSEESENT, BIOCSRTIMEOUT, 
    // todo BIOCGRTIMEOUT, BIOCGSTATS, BIOCGHDRCMPLT, BIOCGSEESENT, 
    // todo BIOCIMMEDIATE, research about these flags

    // Allocate the buffer to hold packets
    bpf_buff = new struct bpf_hdr[bpf_buff_len];
    return (bpf_sock_fd);
}


char
*packets::bpf_read()
{
    // todo: dynamic filter, not static icmp
    int readBytes;
    char *ptr;
    ether_header_t *eth_hdr;
    ipv4_header_t *ip_hdr;
    icmp_header_t *icmp_hdr;

    while (1)
    {
        memset(bpf_buff, 0, bpf_buff_len);
        readBytes = read(bpf_sock_fd, bpf_buff, bpf_buff_len);
        if (readBytes > 0)
        {
            ptr = reinterpret_cast<char *>(bpf_buff);
            while (ptr < (reinterpret_cast<char *>(bpf_buff) + readBytes))
            {
                bpf_packet = reinterpret_cast<bpf_hdr *>(ptr);
                eth_hdr = (ether_header_t*)((char*) bpf_packet + bpf_packet->bh_hdrlen);
                ip_hdr = (ipv4_header_t *)((char*) eth_hdr + sizeof(ether_header_t));
                icmp_hdr = (icmp_header_t *)((char*) ip_hdr + sizeof(ipv4_header_t));

                if (ip_hdr->ip_p == IPPROTO_ICMP) 
                {
                    // Check if it's an ICMP echo request
                    if (icmp_hdr->icmp_type == 8) {
                        std::cout << std::endl << " * receive_bpf: echo request";
                        bpf_print(*eth_hdr, *ip_hdr, *icmp_hdr);
                    }
                    // Check if it's an ICMP echo reply
                    if (icmp_hdr->icmp_type == 0) {
                        std::cout << std::endl << "** receive_bpf: echo reply";
                        bpf_print(*eth_hdr, *ip_hdr, *icmp_hdr);
                    }
                }
                ptr += BPF_WORDALIGN(bpf_packet->bh_hdrlen + bpf_packet->bh_caplen);
            }
        }
    }
    delete[] bpf_buff;
    close(bpf_sock_fd);
    return (NULL);
}