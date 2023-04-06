#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Thomann Yanick, Gachet Jean, Gallay David"
__copyright__   = "Copyright 2023, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "david.gallay@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
MAC_SRC = "90:27:e4:ea:61:f2"
MAC_DEST = "00:00:00:00:00:00"

from zlib import crc32

def compute_icv(payload):
    # TODO: extract payload if parameter is a packet
    return crc32(payload)



def save_pkt(pkt, append=True):
    wrpcap('forged.cap', pkt, append=append)  # Write packet to file

def arp_llc():
    return LLC(b"\xaa\xaa\x03\x00\x00\x00\x08\x06")

def get_fcfield(to_ds=False, from_ds=False, mf=False, retry=False, pw_mgt=False, md=False, wep=False, order=False):
    flags = (to_ds, from_ds, mf, retry, pw_mgt, md, wep, order)
    mask = "".join(str(1 if f else 0) for f in reversed(flags))
    return int(mask, 2)

def default_dot11():
    return Dot11(
        type=2,     # Data
        subtype=0,  # Data
        proto=0,
        FCfield=get_fcfield(to_ds=True, wep=True),  # Flags like FromDS, ToDS, ...
        addr1="00:1d:7e:bd:9e:a0",
        addr2=MAC_SRC,
        addr3=MAC_BROADCAST,
    )

def arp(mac_src, ip_src, mac_dest, ip_dest, llc=True):
    pkt = ARP(hwsrc=mac_src, psrc=ip_src, hwdst=mac_dest, pdst=ip_dest)
    if llc:
        pkt = arp_llc() / pkt
    return pkt

def pkt2bytearray(pkt):
    # str(pkt)  # => explain content
    return bytearray.fromhex(hexstr(pkt, onlyhex=True))


def encrypt(pkt, key, iv):
    if not iv:
        iv = CryptAlgo(...).generate_iv()
    seed = iv + key
    content = pkt2bytearray(pkt)
    icv = compute_icv(content)
    cipher = RC4(seed, streaming=False)
    print(icv)
    ciphertext = cipher.crypt(
        content
        # + icv.to_bytes(4, "big")
    )
    crc = compute_icv(ciphertext)
    res = Dot11WEP(
        iv=iv, wepdata=ciphertext,
        icv=int("ecb3fa23", 16),
        # icv=crc,
        )
    return res


ref_pkt = rdpcap('arp.cap')[0]
ref_pkt_wep = ref_pkt[Dot11WEP]

#Cle wep AA:AA:AA:AA:AA
KEY = b'\xaa\xaa\xaa\xaa\xaa'
# IV = b'\x00' * 3
IV = b'\x0c\x4d\x5c'

pkt = arp(MAC_SRC, "192.168.1.100", MAC_DEST, "192.168.1.200",)
print(pkt2bytearray(pkt).hex())

# déchiffrement rc4
encrypted_pkt = encrypt(pkt, KEY, IV)

tmp = ref_pkt.copy()
tmp[Dot11WEP] = encrypted_pkt
encrypted_pkt = tmp
print(encrypted_pkt.wepdata.hex())
print(ref_pkt_wep.wepdata.hex())
print("-----------------")
print("Packet 1:            ", pkt2bytearray(encrypted_pkt).hex())
print("Reference Packet WEP:", pkt2bytearray(ref_pkt_wep).hex())
print("-----------------")
print("Packet 1:        ", "({})".format(repr(ref_pkt)))
print("-----------------")
print("Reference Packet:", "({})".format(repr(encrypted_pkt)))

save_pkt(ref_pkt, False)
save_pkt(encrypted_pkt, True)
e2 = default_dot11() / encrypt(arp(MAC_SRC, "192.168.1.113", MAC_DEST, "192.168.1.150",), KEY, IV)
save_pkt(e2, True)
