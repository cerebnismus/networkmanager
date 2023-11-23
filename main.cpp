#include "packets.hpp"

int main()
{
    packets net_socket;

    net_socket.send_sock("8.8.8.8");
    net_socket.init_bpf(2, "en0");
    net_socket.receive_bpf();
}