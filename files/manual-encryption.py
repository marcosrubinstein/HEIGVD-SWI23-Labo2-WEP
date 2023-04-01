#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a message with a given wep key"""

__author__      = "Tissot-Daguette Olivier, Bailat Joachim, Valzino Benjamin"

from scapy.all import *
import binascii
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

#IV
iv= b'\x0c\x0c\x0c'
seed = iv + key
keystream = RC4(seed, streaming=False)

arp_packet = ARP(op="who-has", hwsrc="00:11:22:33:44:55", pdst="172.16.20.1")

snap_packet = SNAP(OUI=0, code=0x0806) / arp_packet

llc_packet = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) / snap_packet

icv = struct.pack('I', binascii.crc32(bytes(llc_packet)))

data = llc_packet / icv

#data_encrypted = keystream.crypt(bytes(data))

#wep_header = Dot11WEP(iv=iv, keyid=0x00)

dot11 = Dot11(type=2, addr1="aa:bb:cc:dd:ee:ff", addr2="00:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff", FCfield=['to-DS']) #/ wep_header , 'protected'

radioTapWEP = RadioTap() / dot11 / llc_packet #data_encrypted

wrpcap("temp.cap", radioTapWEP)
