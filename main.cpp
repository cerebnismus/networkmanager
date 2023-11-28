#include "packets.hpp"
#include <pthread.h>

void
sigint_handler(int signal) 
{
        printf(" - SIGINT signal received.\n");

        packets packets;
        // Close the socket if its opened
        if (packets.bpf_sock_fd > 0) close(packets.bpf_sock_fd);
        if (packets.craft_sock_fd > 0) close(packets.craft_sock_fd);
}

void 
*receive_bpf_thread(void *ifname_arg)
{
    packets packets_bpf;
    packets_bpf.bpf_init((const char *)ifname_arg);    // ifname
    packets_bpf.bpf_read();
    return NULL;
}

struct 
ThreadArgs {
    const char *interface_arg;
    const char *dest_ip_arg;
};

void 
*craft_socket_thread(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    packets packets_bpf;
    packets_bpf.craft_socket(args->interface_arg, args->dest_ip_arg);
    delete args; // free the allocated memory
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
    pthread_create(&send_sock_thread_id, NULL, craft_socket_thread, args);

    pthread_join(receive_bpf_thread_id, NULL);
    pthread_join(send_sock_thread_id, NULL);

    signal(SIGINT, sigint_handler);

    exit(0);
}