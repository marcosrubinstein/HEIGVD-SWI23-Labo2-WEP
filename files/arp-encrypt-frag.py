#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 18.04.2023

from scapy.all import *
import binascii
from rc4 import RC4

#Clé wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

#IV récupéré du paquet fournit
iv= b'\x0c\x4d\x5c'
#Creation de la seed / iv + key
seed = iv+key

#texte de la trame
data = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
#separe les données en 3 fragments
NbFrag = 3
fragments = [data[i:i+len(data)//NbFrag] for i in range(0, len(data), len(data)//NbFrag)]

# genere le keystream
cipher = RC4(seed, streaming=False)

packets = []
for i in range(len(fragments)):
    # on crée la trame
    arp = arp = rdpcap('arp.cap')[0]
    arp.iv = iv
    # calcule de l'icv
    icv = binascii.crc32(fragments[i]).to_bytes(4, byteorder='little')
    
    payload = fragments[i] + icv
    # chiffrement du payload
    ciphertext = cipher.crypt(payload)
    # ajout du fragment à la trame
    arp.wepdata = ciphertext[:-4]
    arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
    # ajout du numéro de fragment
    arp.SC = i
    # More fragment à 1 si ce n'est pas le dernier fragment
    arp.FCfield.MF = i < (len(fragments) - 1)
	
    packets.append(arp)
#ecriture des fragments sur un fichier pcap
wrpcap("arpFragEncrypt.cap", packets)