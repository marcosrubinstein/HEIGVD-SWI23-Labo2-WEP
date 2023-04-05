#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Titre: manual_encryption.py
Sujet: HEIGVD-SWI23-Labo2-WEP
Description: 
    Chiffre un message et crée une trame WEP
    Inspiré de manual_decryption.py
Auteurs:
    - Anthony Coke
    - Guilain Mbayo
    - Mehdi Salhi
Date: 05.04.2023
"""

from scapy.all import *
import binascii
from rc4 import RC4
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# lecture d'un message existant pour avoir un template
arp = rdpcap('arp.cap')[0]  

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# Message à chiffrer
message_plain = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xca\xfe\xca'

icv_plain = binascii.crc32(message_plain).to_bytes(4, byteorder='little')

print("Message plain: ", message_plain)
print("Computed ICV: ", icv_plain)

payload_plain = message_plain + icv_plain

# chiffrement rc4
cipher = RC4(seed, streaming=False)
payload_encrypted=cipher.crypt(payload_plain)

# modifie la trame originale
arp.icv = struct.unpack('!L',payload_encrypted[-4:])[0]
arp.wepdata = payload_encrypted[:-4]

# sauvegarde la trame dans un fichier
wrpcap('encrypted.pcap', arp)
