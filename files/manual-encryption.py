#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Manually encrypt a WEP message given the WEP key"""

__author__ = "Abraham Rubinstein"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
import struct

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# Définition de notre message en hexa
data = bytes.fromhex('556E6D6573736167657375757575706572736563726574')

# Calcul de l'ICV en byte
icv = binascii.crc32(data).to_bytes(4, 'little')

# Les données + l'icv forment le plaintext
ptext = data + icv

# rc4 seed est composé de IV+clé
seed = arp.iv + key

# Chiffrement RC4
cipher = RC4(seed, streaming=False)
ctext = cipher.crypt(ptext)

# le ICV est les derniers 4 octets - je le passe en format Long big endian

icv_encrypted = struct.unpack('!L', ctext[-4:])[0]

print('Text: ', ctext[:-4])
print('icv:  ', icv_encrypted)

# On met la length à None pour que Scapy recalcule la longueur lui-même
arp[RadioTap].len = None

# On construit notre trame avec le message chiffré et l'icv
arp.wepdata = ctext[:-4]
arp.icv = icv_encrypted

# On enregistre dans le fichier pcap
wrpcap('forged_tram.pcap', arp)
