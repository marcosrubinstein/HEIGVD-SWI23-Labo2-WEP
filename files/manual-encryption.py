#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message with a WEP key"""

__author__      = "Hugo Jeanneret, Pascal Perrenoud"
__copyright__   = "Copyright 2023, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "pascal.perrenoud@heig-vd.ch, hugo.jeanneret@heig-vd.ch"
__status__ 		= "Final"

from scapy.all import *
import binascii
from rc4 import RC4
from scapy.layers.dot11 import RadioTap

# Réutilisation du paquet comme template de paquet
arp = rdpcap('arp.cap')[0]
arp[RadioTap].len = None # Retire la taille du paquet afin que Scapy calcule la taille correcte à l'écriture

# Clé wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# Payload du paquet
data = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xca\xfe\xca\xfe\xca\xfe\xff\xff\xff\xff\xff\xfe\xca\xfe\xca\xfe\x7f\x00\x00\x01'
icv = struct.pack('<L', binascii.crc32(data))

# Chiffrement du paquet
plain = data + icv
seed = arp.iv+key
cipher = RC4(seed, streaming=False).crypt(plain)

# Remplace les parties du paquet
arp.wepdata = cipher[:-4]
arp.icv = struct.unpack('!L', cipher[-4:])[0]

# Écrit le nouveau paquet
wrpcap('manual.cap', arp)
