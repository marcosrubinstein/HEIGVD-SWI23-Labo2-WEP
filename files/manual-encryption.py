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
import binascii
from rc4 import RC4

# Message à chiffrer
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
# IV trouvé dans le fichier de capture (arp.cap)
iv = b'\x0c\x4d\x5c' 

# rc4 seed est composé de IV+clé
seed = iv+key

# calcul de l'icv
icv = binascii.crc32(message).to_bytes(4, byteorder='little')

# payload à chiffrer
payload = message + icv

# chiffrement rc4
cipher = RC4(seed, streaming=False)
ciphertext = cipher.crypt(payload)

# on crée la trame
arp = arp = rdpcap('arp.cap')[0]
arp.wepdata = ciphertext[:-4]
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
arp.iv = iv

# on exporte la trame
wrpcap('arp-encrypt.cap', arp)
