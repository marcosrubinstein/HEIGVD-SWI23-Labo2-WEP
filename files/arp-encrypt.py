#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description : Script permettant d'encrypter un message wep
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023

""" Manually encrypt a wep message given the WEP key"""

from scapy.all import *
import binascii
from rc4 import RC4



#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# texte de la trame
data = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'

# icv de la trame
icv = binascii.crc32(bytes(data)).to_bytes(4, byteorder='little')

# encrypt the wep message in argument and create a pcap file with the encrypted message
# rc4 seed est composé de IV+clé, IV trouvable sur le fichier arp.cap
iv= b'\x0c\x4d\x5c' 
seed = iv+key

# chiffrement rc4
cipher = RC4(seed, streaming=False)
payload = data + icv
message_encrypted = cipher.crypt(payload)

#Création d'un paquet ARP
arp = arp = rdpcap('arp.cap')[0]
arp.wepdata = message_encrypted[:-4]
arp.icv = struct.unpack('!L', message_encrypted[-4:])[0]
arp.iv = iv
wrpcap('arp-encrypt.cap', arp)