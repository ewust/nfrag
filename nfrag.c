#include <stdlib.h>
#include <stdio.h>


#define __USE_GNU
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <getopt.h>

#define BUFSIZE 9000

#define IP_MF 0x2000

struct config {
    unsigned char   *filter_keyword;  // Keyword to filter on
    uint32_t        filter_keyword_len;

    unsigned char   replace;
    int             ttl;

    int             rawsock;
};

uint16_t csum(uint16_t *buf, int nwords, uint32_t init_sum)
{
    uint32_t sum;

    for (sum=init_sum; nwords>0; nwords--) {
        sum += ntohs(*buf++);
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

void ip_checksum(struct iphdr *ip)
{
    ip->check = htons(csum((uint16_t *)ip, ip->ihl*2, 0));
}

int fragment_packet(struct iphdr *ip, int frag_offset, int len, struct config *conf)
{
    int iphdr_len = ip->ihl*4;
    unsigned char *data = &((unsigned char *)ip)[iphdr_len];
    int data_len = len - iphdr_len;
    if (data_len < 0) {
        return -1;
    }


    int data_frag_offset = frag_offset - iphdr_len; // Offset into the data that we want to fragment
                                                    // round this up to the next (or current) 8-byte boundary
    data_frag_offset += (8 - (data_frag_offset % 8));
    if (data_frag_offset >= data_len) {
        return -1;
    }

    struct iphdr *frag1, *frag2, *frag3;
    int frag1_len = iphdr_len + data_frag_offset;
    int frag2_len = len - data_frag_offset;
    int frag3_len = frag2_len;

    frag1 = malloc(frag1_len);
    frag2 = malloc(frag2_len);
    frag3 = malloc(frag3_len);

    // Fragment 1
    memcpy(frag1, ip, iphdr_len);
    frag1->frag_off = htons(IP_MF);
    frag1->tot_len = htons(frag1_len);
    unsigned char *frag1_data = &((unsigned char *)frag1)[iphdr_len];
    memcpy(frag1_data, data, data_frag_offset);
    ip_checksum(frag1);

    // Fragment 2
    memcpy(frag2, ip, iphdr_len);
    frag2->frag_off = htons(data_frag_offset/8);
    frag2->tot_len = htons(frag2_len);
    unsigned char *frag2_data = &((unsigned char *)frag2)[iphdr_len];
    memcpy(frag2_data, &data[data_frag_offset], data_len - data_frag_offset);
    ip_checksum(frag2);

    // Fragment 3 (copy of frag2, with lower TTL and different data)
    memcpy(frag3, frag2, iphdr_len);
    frag3->ttl = conf->ttl;
    unsigned char *frag3_data = &((unsigned char *)frag3)[iphdr_len];
    memset(frag3_data, conf->replace, data_len - data_frag_offset);
    ip_checksum(frag3);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;   //???

    // Send 1, 3, 2
    sin.sin_addr.s_addr = frag1->daddr;
    sendto(conf->rawsock, frag1, frag1_len, 0, (struct sockaddr*)&sin, sizeof(sin));

    sin.sin_addr.s_addr = frag3->daddr;
    sendto(conf->rawsock, frag3, frag3_len, 0, (struct sockaddr*)&sin, sizeof(sin));

    sin.sin_addr.s_addr = frag2->daddr;
    sendto(conf->rawsock, frag2, frag2_len, 0, (struct sockaddr*)&sin, sizeof(sin));

    free(frag1);
    free(frag2);
    free(frag3);
}

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
        fragment_packet((struct iphdr *)payload, (found - payload), len, conf);
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

    conf.rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (conf.rawsock < 0) {
        perror("socket");
        return -1;
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
