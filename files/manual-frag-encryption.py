#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a message in multiple fragments with a given wep key and a given IV"""
""" WARNING will work only if the packet that we have to fragment can be divided by nbrFrag without rest (padding not supported)"""

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

#Nombre de fragments à créer (Max 16)
nbrFrag = 3

#FCfield en fonction de s'il s'agit du dernier fragment ou non
FCfieldFrag = ['to-DS', 'protected', 'MF']
FCfieldLastFrag = ['to-DS', 'protected']

#Création de la seed (composé de l'IV et de la clé WEP) et du keystream
seed = iv + key
keystream = RC4(seed, streaming=False)

#Création d'un paquet ARP
arp_packet = ARP(op="who-has", hwsrc="00:11:22:33:44:55", pdst="172.16.20.1")

#Ajout de l'entête SNAP au paquet ARP
snap_packet = SNAP(OUI=0, code=0x0806) / arp_packet

#Ajout de l'entête LLC au paquet SNAP + ARP
data = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) / snap_packet

#Permet de connaitre la taille qu'aura chaque fragment (pas de padding)
tailleFrag = int(len(data) / nbrFrag)

packets = []

for i in range(nbrFrag):

	#Fragmentation du paquet
	dataFrag = bytes(data)[i*tailleFrag:(1+i)*tailleFrag]
	
	#Calcul de l'ICV sur le fragment créé
	icv = binascii.crc32(bytes(dataFrag)).to_bytes(4, byteorder='little')

	#Chiffrage du fragment créé
	data_encrypted = keystream.crypt(bytes(dataFrag) + icv)

	#Création du header WEP afin de spécifier l'IV, les données et l'IVC
	wep_header = Dot11WEP(iv=iv, keyid=0x00, wepdata=bytes(data_encrypted[:-4]), icv=struct.unpack('!L', data_encrypted[-4:])[0])

	#Création du header 802.11 avec les différentes adresses MAC et spécification des bits FCfield nécessaire (ici to-DS, protected et s'il ne s'agit pas du dernier fragment alors "MP" est rajouté)
	dot11 = Dot11(type=2, addr1="aa:bb:cc:dd:ee:ff", addr2="00:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff", FCfield=FCfieldFrag if i != nbrFrag - 1 else FCfieldLastFrag, SC=i) / wep_header

	#Création du fragment
	packet = RadioTap() / dot11 / data_encrypted
	
	#Sauvegarde du fragment dans un tableau pour l'export
	packets.append(packet)
	
#Export des fragments
wrpcap("arpFragEncrypt.cap", packets)
