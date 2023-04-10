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

# See pdf Ch2 WEP, p.31

MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
MAC_BSS = "00:1d:7e:bd:9e:a0"
MAC_SRC = "90:27:e4:ea:61:f2"
MAC_DEST = "00:00:00:00:00:00"


import os

def generate_iv():
    return os.urandom(3)


from zlib import crc32

def compute_icv(payload):
    # TODO: extract payload if parameter is a packet
    return crc32(payload).to_bytes(4, "little")



def save_pkt(pkt, append=True):
    wrpcap('forged.cap', pkt, append=append)  # Write packet to file

# def arp_llc():
#     return LLC(b"\xaa\xaa\x03\x00\x00\x00\x08\x06")

# Nb: we can use list of string instead
# def get_fcfield(to_ds=False, from_ds=False, mf=False, retry=False, pw_mgt=False, md=False, wep=False, order=False):
#     flags = (to_ds, from_ds, mf, retry, pw_mgt, md, wep, order)
#     mask = "".join(str(1 if f else 0) for f in reversed(flags))
#     return int(mask, 2)

def default_dot11():
    return Dot11(
        type=2,     # Data
        subtype=0,  # Data
        proto=0,
        # FCfield=get_fcfield(to_ds=True, wep=True),  # Flags like FromDS, ToDS, ...
        FCfield=['to-DS', 'protected'],
        addr1=MAC_BSS,
        addr2=MAC_SRC,
        addr3=MAC_BROADCAST,
    )

def arp(mac_src, ip_src, mac_dest, ip_dest, llc=True, snap=True):
    """
        This function create a basic ARP trame with optionally(active by default) lcc and snap headers
    """
    # https://scapy.readthedocs.io/en/latest/usage.html#arp-cache-poisoning
    pkt = ARP(op="who-has", hwsrc=mac_src, psrc=ip_src, hwdst=mac_dest, pdst=ip_dest)
    if snap:
        # SNAP ("Subnetwork Access Protocol"): "is a mechanism for multiplexing more protocols than can be distinguished by the 8-bit 802.2 SAP field" (Wikipedia)
        # Organisation Code: 0x00 0x00 0x00
        # Type: ARP (0x08 0x06)
        pkt = SNAP(b"\x00\x00\x00\x08\x06") / pkt
    if llc:
        # LLC ("Logical link control")
        # DSAP ("Destination Service Access Point"): 0xAA
        # SSAP ("Source Service Access Point"): 0XAA
        # => DSAP and SSAP are set to 0xAA to indicate that this is a SNAP frame
        # Control Field: 0X03 => Unnumbered Frame
        pkt = LLC(b"\xaa\xaa\x03") / pkt
    return pkt

def pkt2bytearray(pkt):
    """
        Convert a packet to a bytearray
    """
    # str(pkt)  # => explain content
    # use bytes(pkt) instead ?
    return bytearray.fromhex(hexstr(pkt, onlyhex=True))

def encrypt(pkt, key, iv=None):
    """
        Encrypt a packet:
        - pkt: packet to encrypt
        - key: key for encryption
        - iv (optional): the IV to use (if not provided, a random IV is generated)
        It returns a tuple containing (ciphertext, ICV, IV)
    """
    if not iv:
        iv = generate_iv()
    seed = iv + key
    content = bytes(pkt)
    icv = compute_icv(content)
    cipher = RC4(seed, streaming=False)
    content_with_icv = (
        content
        + icv
    )
    ciphertext = cipher.crypt(
        content_with_icv
    )
    return ciphertext[:-4], struct.unpack('!L', ciphertext[-4:])[0], iv


def pkt2dot11wep(pkt, key, iv=None):
    """

    """
    ciphertext, icv, iv = encrypt(pkt, key, iv)
    res = Dot11WEP(
        iv=iv,
        wepdata=ciphertext,
        icv=icv,
    )
    return res

def demo_arp():
    return arp(MAC_SRC, "192.168.1.113", MAC_DEST, "192.168.1.118")

ref_pkt = rdpcap('arp.cap')[0]
save_pkt(ref_pkt, False)

#Cle wep AA:AA:AA:AA:AA
KEY = b'\xaa\xaa\xaa\xaa\xaa'
IV = b'\x0c\x4d\x5c'

pkt = arp(MAC_SRC, "192.168.1.100", MAC_DEST, "192.168.1.200",)

e2 = RadioTap() / default_dot11() / pkt2dot11wep(arp(MAC_SRC, "192.168.1.113", MAC_DEST, "192.168.1.118",), KEY, IV)

save_pkt(e2)
