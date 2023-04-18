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
data = [bytes.fromhex('556E6D657373616765'), bytes.fromhex('7375757575706572'), bytes.fromhex('736563726574')]

# rc4 seed est composé de IV+clé
seed = arp.iv + key

# Chiffrement RC4
cipher = RC4(seed, streaming=False)


for x in range(len(data)):
    # Calcul de l'ICV en byte
    icv = binascii.crc32(data[x]).to_bytes(4, 'little')

    # Les données + l'icv forment le plaintext
    ptext = data[x] + icv

    ctext = cipher.crypt(ptext)

    arp.wepdata = ctext[:-4]
    # le ICV est les derniers 4 octets - je le passe en format Long big endian
    arp.icv = struct.unpack('!L', ctext[-4:])[0]

    print("Fragment ", x)
    print('Text: ', ctext[:-4])
    print('icv:  ', arp.icv)
    print("---------------------------------")

    arp.SC = x
    # More fragment à 1 si ce n'est pas le dernier fragment
    arp.FCfield.MF = x < (len(data) - 1)
    # on supprime la longueur du RadioTap pour que Scapy la calcule
    arp[RadioTap].len = None

    # On enregistre dans le fichier pcap
    wrpcap('forged_tram_frag.pcap', arp, append=(x != 0))
