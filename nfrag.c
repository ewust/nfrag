#include <stdlib.h>
#include <stdio.h>


#define __USE_GNU
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <getopt.h>

#define BUFSIZE 9000

struct config {
    unsigned char   *filter_keyword;  // Keyword to filter on
    uint32_t        filter_keyword_len;

    unsigned char   replace;
    int             ttl;
};

int pkt_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int len;
    struct config *conf = data;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("id %d\n", id);
    }

    len = nfq_get_payload(nfa, &payload);
    if (len < 0) {
        fprintf(stderr, "Error nfq_get_payload %d\n", len);
        exit(1);
    }

    unsigned char *found;
    found = (unsigned char *)memmem(payload, len, conf->filter_keyword, conf->filter_keyword_len);
    if (found != NULL) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void print_help()
{
    printf("nfrag: Fragment IPv4 packets on keyword. When a keyword is detected\n");
    printf("in a packet, create two fragments from it (1 and 2), and send three\n");
    printf("fragments: fragment 1, fragment 3, and fragment 2, where fragment 3\n");
    printf("is a \"disrupt\" fragment, made from a copy of fragment 2 with a\n");
    printf("lower TTL and replaced data\n");
    printf("\n");
    printf("Options:\n");
    printf("    --keyword, -k   string keyword to fragment packets\n");
    printf("    --replace, -r   character to send in the disrupt fragment\n");
    printf("    --ttl, -t       TTL of fragment 3\n");
    printf("\n");
    exit(1);
}


int main(int argc, char *argv[])
{
    int fd;
    int rv;
    int status;
    unsigned char *buf;
    struct nfq_handle *nfqh;
    struct nfq_q_handle *qh;
    struct config conf;
    int c;
    int option_index = 0;
    struct option long_options[] = {
        {"keyword", required_argument, 0, 0},
        {"replace", required_argument, 0, 0},
        {"ttl",     required_argument, 0, 0},
        {0, 0, 0, 0}};


    while ((c = getopt_long(argc, argv, "k:r:t:", long_options, &option_index)) != -1) {

        switch (c) {
            case 'k':
                conf.filter_keyword = optarg;
                conf.filter_keyword_len = strlen(conf.filter_keyword);
                break;
            case 'r':
                conf.replace = optarg[0];
                break;
            case 't':
                conf.ttl = atoi(optarg);
                break;
            case '?':
            default:
                print_help();
        }
    }

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

    qh = nfq_create_queue(nfqh, 0, &pkt_cb, &conf);
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
