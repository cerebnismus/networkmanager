#include "packets.hpp"
#include <pthread.h> /* multi thread */

void 
*send_sock_thread(void *dest_ip_arg)
{
    packets net_socket;
    net_socket.send_sock((const char *)dest_ip_arg);
    return NULL;
}

void 
*receive_bpf_thread(void *ifname_arg)
{
    packets net_socket;
    net_socket.init_bpf(2, (const char *)ifname_arg);    // bpf device and ifname
    net_socket.receive_bpf();
    return NULL;
}


int 
main(int argc, char *argv[])
{
    if (argc != 3) 
    {
        errno = 22;
        perror("Usage:\n\
            \targv[1] : interface name\n\
            \targv[2] : destination ip\n\n");
        _exit(errno);
    }

    pthread_t receive_bpf_thread_id;
    pthread_t send_sock_thread_id;

    pthread_create(&receive_bpf_thread_id, NULL, receive_bpf_thread, argv[1]);
    pthread_create(&send_sock_thread_id, NULL, send_sock_thread, argv[2]);

    pthread_join(receive_bpf_thread_id, NULL);
    pthread_join(send_sock_thread_id, NULL);

    exit(0);
}