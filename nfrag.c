#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define BUFSIZE 9000


int pkt_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("id %d\n", id);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char *argv[])
{
    int fd;
    int rv;
    int status;
    unsigned char *buf;
    struct nfq_handle *nfqh;
    struct nfq_q_handle *qh;

    buf = malloc(BUFSIZE);
    if (!buf) {
        perror("malloc");
        return -1;
    }

    nfqh = nfq_open();
    if (!nfqh) {
        fprintf(stderr, "Error: nfq_open %d\n", status);
        return -1;
    }

    status = nfq_unbind_pf(nfqh, AF_INET);
    if (status < 0) {
        fprintf(stderr, "Error: nfq_unbind_pf %d\n", status);
        return -1;
    }

    status = nfq_bind_pf(nfqh, PF_INET);
    if (status < 0) {
        fprintf(stderr, "Error: nfq_bind_pf %d\n", status);
        return -1;
    }
    printf("got nfq_bind: %d\n", status);

    qh = nfq_create_queue(nfqh, 0, &pkt_cb, NULL);
    if (!qh) {
        fprintf(stderr, "Error: nfq_create_queue\n");
        return -1;
    }

    status = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    if (status < 0) {
        fprintf(stderr, "Error: nfq_set_mode %d\n", status);
        return -1;
    }
    printf("nfq_set_mode: %d\n", status);

    fd = nfq_fd(nfqh);
    printf("listening to fd %d\n", fd);

    while ((rv = recv(fd, buf, BUFSIZE, 0)) && rv >= 0) {
        printf("pkt\n");
        nfq_handle_packet(nfqh, buf, rv);
    }
    printf("done\n");

    nfq_destroy_queue(qh);

    nfq_close(nfqh);
    return 0;
}
