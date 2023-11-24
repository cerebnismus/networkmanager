#include "packets.hpp"
#include <pthread.h> /* multi thread */

void 
*send_sock_thread(void *arg)
{
    packets net_socket;
    net_socket.send_sock((const char *)arg);
    return NULL;
}

void 
*receive_bpf_thread(void *arg)
{
    packets net_socket;
    net_socket.init_bpf(2, "en3");    // bpf device and ifname
    net_socket.receive_bpf();
    return NULL;
}


int 
main(int argc, char *argv[])
{
    if (argc < 2) 
    {
        errno = 22;
        perror("Usage:\n\
            \targv[1] : destination ip\n\n");
        _exit(errno);
    }

    pthread_t receive_bpf_thread_id;
    pthread_t send_sock_thread_id;

    pthread_create(&receive_bpf_thread_id, NULL, receive_bpf_thread, NULL);
    // pthread_create(&send_sock_thread_id, NULL, send_sock_thread, NULL);
    // create send socket thread with destination ip
    pthread_create(&send_sock_thread_id, NULL, send_sock_thread, argv[1]);

    pthread_join(receive_bpf_thread_id, NULL);
    pthread_join(send_sock_thread_id, NULL);

    return 0;
}