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

BROADCAST = "ff:ff:ff:ff:ff:ff"
MAC_SRC = "90:27:e4:ea:61:f2"


def save_pkt(pkt, append=True):
    wrpcap('forged.cap', pkt, append=append)  # Write packet to file

def arp_llc():
    return LLC(b"\xaa\xaa\x03\x00\x00\x00\x08\x06")

def arp(mac_src, ip_src, mac_dest, ip_dest, llc=True):
    pkt = ARP(hwsrc=mac_src, psrc=ip_src, hwdst=mac_dest, pdst=ip_dest)
    if llc:
        pkt = arp_llc() / pkt
    return pkt

def pkt2bytearray(pkt):
    # str(pkt)  # => explain content
    return bytearray.fromhex(hexstr(pkt, onlyhex=True))

def encrypt(pkt, key, iv):
    seed = iv + key
    cipher = RC4(seed, streaming=False)
    ciphertext = cipher.crypt(pkt2bytearray(pkt))
    content = ciphertext + iv
    res = Dot11WEP(iv=iv, wepdata=ciphertext)
    return res



#Cle wep AA:AA:AA:AA:AA
KEY = b'\xaa\xaa\xaa\xaa\xaa'
# IV = b'\x00' * 3
IV = b'\x0c\x4d\x5c'

pkt = arp(MAC_SRC, "192.168.1.100", "00:00:00:00:00:00", "192.168.1.200",)
print(pkt2bytearray(pkt).hex())

# déchiffrement rc4
encrypted_pkt = encrypt(pkt, KEY, IV)

save_pkt(encrypted_pkt, False)
