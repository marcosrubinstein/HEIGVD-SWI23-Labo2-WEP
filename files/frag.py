#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually fragment and encrypt a wep message in three parts, with a WEP key"""

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
from copy import deepcopy
import os

# Fonction pour générer un paquet fragmenté
def gen_pck(ref, key, payload, num, size):
    # Copie le paquet de référence
    pck = deepcopy(ref)

    # Génère un IV
    pck.iv = os.urandom(3)

    # Calcule l'ICV du payload
    icv = struct.pack('<L', binascii.crc32(payload))

    # Chiffre les données
    plain = payload + icv
    seed = pck.iv + key
    cipher = RC4(seed, streaming=False).crypt(plain)

    # Place les données dans le paquet
    pck.wepdata = cipher[:-4]
    pck.icv = struct.unpack('!L', cipher[-4:])[0]
    pck.SC = num
    pck.FCfield.MF = 0 if num == size-1 else 1

    # Retourne le fragment généré
    return pck


# Réutilisation du paquet donné comme template
arp = rdpcap('arp.cap')[0]

# Retire la taille du paquet afin que Scapy calcule la taille correcte à l'écriture du paquet
arp[RadioTap].len = None

# Clé WEP AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# Payload
data = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xca\xfe\xca\xfe\xca\xfe\xff\xff\xff\xff\xff\xfe\xca\xfe\xca\xfe\x7f\x00\x00\x01'

# Split le payload en morceaux égaux
PCK_COUNT = 3
PCK_LEN = math.ceil(len(data) / PCK_COUNT)
data = [data[PCK_LEN*i:(i+1)*PCK_LEN] for i in range(PCK_COUNT)]

# Génération des paquets
print(f"Génération de {len(data)} fragments")
pckts = [gen_pck(arp, key, d, i, len(data)) for i, d in enumerate(data)]

# Écriture des nouveaux paquets
wrpcap('frag.cap', pckts)
