#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Melissa Gehring, Maelle Vogel, Maxim Golay"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "melissa.gehring@heig-vd.ch, maelle.vogel@heig-vd.ch, maxim.golay@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from scapy.layers.dot11 import RadioTap
import binascii
from rc4 import RC4

# Message à chiffrer and fragments
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
fragments = [message[i:i+int(len(message)/3)] for i in range(0, len(message), int(len(message)/3))]

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
# Même IV que pour la partie précédente
iv = b'\x0c\x4d\x5c' 

# rc4 seed est composé de IV+clé
seed = iv+key

# generation key stream RC4
cipher = RC4(seed, streaming=False)

# on crée la trame
arp = arp = rdpcap('arp.cap')[0]
arp.iv = iv

# pour chaque fragment
for i in range(len(fragments)):
    # on calcule l'icv
    icv = binascii.crc32(fragments[i]).to_bytes(4, byteorder='little')
    # payload à chiffrer
    payload = fragments[i] + icv
    # chiffrement rc4
    ciphertext = cipher.crypt(payload)
    # on ajoute le fragment chiffré à la trame
    arp.wepdata = ciphertext[:-4]
    arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
    # Compteur de fragment incrémenté
    arp.SC = i
    # More fragment à 1 si ce n'est pas le dernier fragment
    arp.FCfield.MF = i < (len(fragments) - 1)
    # on supprime la longueur du RadioTap pour que Scapy la calcule
    arp[RadioTap].len = None

    # on append le fragment à la trame
    wrpcap('arp-encrypt-fragment.cap', arp, append=(i != 0))

