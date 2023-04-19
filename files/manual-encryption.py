#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import binascii
from rc4 import RC4
from scapy.layers.dot11 import RadioTap

# Réutilisation du paquet comme template de paquet
arp = rdpcap('arp.cap')[0]

# Clé wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
seed = arp.iv+key
rc = RC4(seed, streaming=False)

# Payload du paquet
data = b'HEIG{My fancy flag}'
icv = struct.pack('<L', binascii.crc32(data) & 0xffffffff)

# Chiffrement du paquet
plain = data + icv
cipher = rc.crypt(plain)

# Remplace les parties du paquet
arp.wepdata = cipher[:-4]
arp.icv = struct.unpack('!L', cipher[-4:])[0]

# Écrit le nouveau paquet
arp[RadioTap].len = None
wrpcap('manual.cap', arp)
