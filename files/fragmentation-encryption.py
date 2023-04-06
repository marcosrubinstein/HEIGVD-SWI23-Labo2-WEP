
from scapy.all import *
from manual_encryption import (
    demo_arp,
    compute_icv, pkt2dot11wep,
    encrypt,
    default_dot11,
    IV, KEY
)
import math


def _fragment_pkt(pkt, key, iv, start, end, more_frag=False):
    dot11 = default_dot11()
    if more_frag:
        dot11.FCfield = ["to-DS", "protected"]
    else:
        dot11.FCfield = ["to-DS", "protected", "MF"]

    pkt = RadioTap() / dot11 / pkt2dot11wep(bytes(pkt)[start:end], key, iv)
    return pkt


def fragment_pkt(pkt, key, iv, size=None, count=None):
    if not count and not size:
        raise Exception("you need to provide either size or count parameters")
    pkt_size = len(pkt)
    if count:
        size = int(pkt_size / count)
    else:
        count = math.ceil(pkt_size / size)
    for i in range(0, pkt_size, size):
        print(i)
        yield _fragment_pkt(pkt, key, iv, i , i + size)

pkt = demo_arp()
packets = list(fragment_pkt(pkt, KEY, IV, count=3))
print(packets)
wrpcap('forged_fragmented.cap', packets, append=False)
