#!/usr/bin/python

import dnet
import random
import socket
import dpkt
import sys
import math
import time

DEFAULT_RESOLVER='4.2.2.1'


def get_ip():
    return socket.gethostbyname_ex(socket.gethostname())[2][0]

def make_dns_request_payload(domain, txid=None):
    if txid == None:
        txid = random.randint(0, 0xffff)

    dns = dpkt.dns.DNS(id=txid)
    #dns.op &= ~dpkt.dns.DNS_RD # no recurse
    dns.qd = [ dpkt.dns.DNS.Q(name=domain) ]

    return dns


def make_dns_pkt(domain, txid=None, sport=None, dport=53, srcip=None, dstip=DEFAULT_RESOLVER, ipid=None, ipttl=128):
    if sport == None:
        sport = random.randint(32768, 61000)

    if srcip == None:
        srcip = get_ip()

    if ipid == None:
        ipid = random.randint(0,0xffff)

    dns = make_dns_request_payload(domain, txid)

    udp = dpkt.udp.UDP(sport=sport, dport=dport)
    udp.data = dns
    udp.ulen += len(udp.data)

    pkt = dpkt.ip.IP(src=socket.inet_aton(srcip), dst=socket.inet_aton(dstip), p=0x11, ttl=ipttl, id=ipid)

    pkt.data = udp
    pkt.len += len(str(pkt.data))
    pkt.data.sum = 0
    pkt.sum = 0

    return pkt


# returns num_frags fragments, or, if fragment_in is a string, fragments
# across the first occurance of that string in the payload
# e.g. "ABCDEFGHIJKLMNO" with fragment_in="HI" will make
# "ABCDEFGH" and "IJKLMNO"
# note that we can only fragment on 8-byte boundaries
def get_fragments(ip_pkt, num_frags=2, fragment_in=None):

    x = str(ip_pkt)
    hdr = dpkt.ip.IP(src=ip_pkt.src, dst=ip_pkt.dst, p=ip_pkt.p, ttl=ip_pkt.ttl, id=ip_pkt.id, off=dpkt.ip.IP_MF, sum=ip_pkt.sum, len=ip_pkt.len)

    data = str(ip_pkt.data)
    data_len = len(data)

    offset = 0

    if fragment_in is not None:
        if fragment_in not in data:
            raise Exception('Fragment not in string')
        idx = data.index(fragment_in)
        if len(fragment_in) < (8 - (idx % 8)):
            raise Exception('Cannot fragment within specified string')

        idx += (8 - (idx % 8))
        num_frags = 2
        off_step = idx
    else:
        blocks = (data_len + 7) / 8
        off_step = 8*int(math.ceil(float(blocks)/num_frags))


    for i in xrange(num_frags):
        cur_pkt = hdr
        cur_pkt.sum = 0
        if i != (num_frags - 1):
            cur_pkt.off = dpkt.ip.IP_MF | ((offset/8) & dpkt.ip.IP_OFFMASK)
        else:
            cur_pkt.off = (offset/8) & dpkt.ip.IP_OFFMASK

        cur_pkt.data = data[offset:offset+off_step]
        cur_pkt.len = len(cur_pkt.data) + 20
        offset += off_step


        yield cur_pkt

net = dnet.ip()
dns = make_dns_pkt("twitter.com", srcip=sys.argv[1])


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(('eth0', 0))

def mac(x):
    return x.replace(':', '').decode('hex')

def send(pkt):
    global s

    #src = 'e8:2a:ea:5d:e9:f9'
    src = '28:d2:44:9a:8e:60'
    #dst = '00:23:33:ed:d4:14'
    #dst = 'e8:40:40:9b:42:40'
    dst = 'f8:66:f2:28:fd:3f'

    s.send(mac(dst) + mac(src) + '\x08\x00' + pkt)

#send(str(dns))

for pkt in get_fragments(dns, fragment_in='twitter'):
    print pkt.__repr__()
    send(str(pkt))
    #time.sleep(1)


#net.send(str(dns))


