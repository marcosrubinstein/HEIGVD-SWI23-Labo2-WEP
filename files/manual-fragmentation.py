#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Titre: manual_fragmentation.py
Sujet: HEIGVD-SWI23-Labo2-WEP
Description: 
    Fragmente et chiffre une trame
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
arp[RadioTap].len = None

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# divine un message en n partie
def split_string(string, n):
    # Calculer la longueur de chaque sous-chaîne
    split_size = len(string) // n
    
    # Diviser la chaîne en sous-chaînes de longueur égale
    parts = [string[i:i+split_size] for i in range(0, len(string), split_size)]
    
    return parts

# Message à chiffrer
# Il s'agit du même message que dans manual_encryption mais avec des bytes
# modifiées en '0xca0xfe'


message_plain = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xfe\xca\xca\xfe\xca'

nb_frag = 3

# messages divisé en n fragments
frags = split_string(message_plain, nb_frag)

# RC4
cipher = RC4(seed, streaming=False)

for i in range(0, nb_frag):
    arp_f = arp

    # Set le numéro de séquence
    arp_f.SC = i

    # set le bit More Fragment pour tous les fragments sauf le dernier
    arp_f.FCfield.MF = 0 if (i == nb_frag -1) else 1

    # calcul l'ICV
    icv_plain = binascii.crc32(frags[i]).to_bytes(4, byteorder='little')

    # Concatene le fragment a l'ICV correspondant pour créer le payload
    payload_plain = frags[i] + icv_plain

    # chiffre le payload
    payload_encrypted=cipher.crypt(payload_plain)

    # set l'icv et les données wep
    arp_f.icv = struct.unpack('!L',payload_encrypted[-4:])[0]
    arp_f.wepdata = payload_encrypted[:-4]

    # sauvegarde les 3 trames fragmentées dans un fichier
    wrpcap('fragmented.pcap', arp_f, append=False if i == 0 else True)
