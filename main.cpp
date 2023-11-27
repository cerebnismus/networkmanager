#include "packets.hpp"
#include <pthread.h> /* multi thread */

void 
*receive_bpf_thread(void *ifname_arg)
{
    packets net_socket;
    net_socket.init_bpf(2, (const char *)ifname_arg);    // bpf device and ifname
    net_socket.receive_bpf();
    return NULL;
}

struct 
ThreadArgs {
    const char *interface_arg;
    const char *dest_ip_arg;
};

void 
*send_sock_thread(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    packets net_socket;
    net_socket.send_sock(args->interface_arg, args->dest_ip_arg);
    delete args; // Don't forget to free the allocated memory
    return (NULL);
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

    ThreadArgs *args = new ThreadArgs{argv[1], argv[2]};
    pthread_create(&send_sock_thread_id, NULL, send_sock_thread, args);

    pthread_join(receive_bpf_thread_id, NULL);
    pthread_join(send_sock_thread_id, NULL);

    exit(0);
}