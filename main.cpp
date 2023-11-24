#include "packets.hpp"
#include <pthread.h> /* multi thread */

void *send_sock_thread(void *arg)
{
    packets net_socket;
    net_socket.send_sock("8.8.8.8");  // target IP (Google DNS)
    return NULL;
}

void *receive_bpf_thread(void *arg)
{
    packets net_socket;
    net_socket.init_bpf(2, "en3");    // bpf device and ifname
    net_socket.receive_bpf();
    return NULL;
}

// take i as an arg
int main(int argc, char **argv)
{
    pthread_t receive_bpf_thread_id;
    pthread_t send_sock_thread_id;

    pthread_create(&receive_bpf_thread_id, NULL, receive_bpf_thread, NULL);
    pthread_create(&send_sock_thread_id, NULL, send_sock_thread, NULL);

    pthread_join(receive_bpf_thread_id, NULL);

    for (int i = atoi(argv[1]); i < 10; i++)
    {
        pthread_join(send_sock_thread_id, NULL);
    }

    return 0;
}