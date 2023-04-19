#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a message with a given wep key and a given IV"""

__author__      = "Tissot-Daguette Olivier, Bailat Joachim, Valzino Benjamin"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "olivier.tissot-daguette@heig-vd.ch, joachim.bailat@heig-vd.ch, benjamin.valzino@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

#Clé wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

#IV récupéré du paquet fournit
iv= b'\x0c\x4d\x5c' 

#Création de la seed (composé de l'IV et de la clé WEP) et du keystream
seed = iv + key
keystream = RC4(seed, streaming=False)

#Création d'un paquet ARP
arp_packet = ARP(op="who-has", hwsrc="00:11:22:33:44:55", pdst="172.16.20.1")

#Ajout de l'entête SNAP au paquet ARP
snap_packet = SNAP(OUI=0, code=0x0806) / arp_packet

#Ajout de l'entête LLC au paquet SNAP + ARP
data = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) / snap_packet

#Calcul de l'ICV sur le paquet contenant LLC + SNAP + ARP
icv = binascii.crc32(bytes(data)).to_bytes(4, byteorder='little')

#Chiffrage des données (LLC + SNAP + ARP + ICV)
data_encrypted = keystream.crypt(bytes(data) + icv)

#Création du header WEP afin de spécifier l'IV, les données et l'IVC
wep_header = Dot11WEP(iv=iv, keyid=0x00, wepdata=bytes(data_encrypted[:-4]), icv=struct.unpack('!L', data_encrypted[-4:])[0])

#Création du header 802.11 avec les différentes adresses MAC et spécification des bits to-DS et protected (pour WEP) dans le champ FCfield
dot11 = Dot11(type=2, addr1="aa:bb:cc:dd:ee:ff", addr2="00:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff", FCfield=['to-DS', 'protected']) / wep_header

#Création du paquet final
packet = RadioTap() / dot11 / data_encrypted

#Export du paquet
wrpcap("arpEncrypt.cap", packet)
