
from scapy.all import *
from manual_encryption import (
    demo_arp,
    compute_icv, pkt2dot11wep,
    default_dot11,
    generate_iv,
    IV, KEY
)
import math


def _fragment_pkt(pkt, key, iv, index, start, end, more_frag=None):
    """
        C'est une fonction utilitaire

        Cette fonction prend un packet et en extrait un fragment.
        Le fragment extrait est chiffré et encapsulé dans WEP.
        - pkt: le paquet source à fragmenter
        - key: la clef de chiffrement WEP
        - iv: l'IV de chiffrement WEP. Si vaut None, un IV aléatoire est généré.
        - index: index du fragment (commence à 0)
        - start: byte de début du fragment à extraire
        - end: byte de fin (non compris) du fragment à extraire
        - more_frag: Permet de forcer la valeur du flag "More Fragment".
                     Par défaut, cette valeur est calculé selon le paramètre `end` et la longueur du paquet
    """
    dot11 = default_dot11()
    pkt_bytes = bytes(pkt)

    # Calcule la valeur du flag `More Frag` si la valeur n'est pas forcée en paramètre
    if more_frag is None:
        more_frag = end < len(pkt_bytes)
    # Génère un IV si aucun IV n'est fournit.
    if iv is None:
        iv = generate_iv()
    # Définit les flags de la trame.
    if more_frag:
        dot11.FCfield = ["to-DS", "MF", "protected"]
    else:
        dot11.FCfield = ["to-DS", "protected"]
    # Définit l'index de la trame
    dot11.SC = index
    # Chiffre+encapsule la trame et ajoute les entêtes
    pkt = RadioTap() / dot11 / pkt2dot11wep(pkt_bytes[start:end], key, iv)
    return pkt


def fragment_pkt(pkt, key, iv=None, /, size=None, count=None):
    """
        Cette fonction prend un packet et le découpe en fragments
        Les fragments extraits sont chiffrés et encapsulés dans WEP.
        - pkt: le paquet source à fragmenter
        - key: la clef de chiffrement WEP
        - iv: l'IV de chiffrement WEP. Si vaut None, un IV aléatoire est généré pour chaque fragment.
        - size: taille (maximum) des fragments (ce paramètre est ignoré si `count` est définit)
        - count: nombre de fragment à générer (se paramètre à la priorité sur `size`)
        Nb:
            - il faut obligatoire fournir soit `size`, soit `count`, il ne sert à rien de fournir les 2 paramètres.
            - Les paramètres `size` et `count` sont obligatoirement des paramètres nommés et non positionnels
            - Cette fonction est un générateur (mot-clef `yield`).

    """
    if not count and not size:
        raise Exception("you need to provide either size or count parameter")
    # Calcule la contre-partie de size/count.
    pkt_size = len(pkt)
    if count:
        size = int(pkt_size / count)
    else:
        count = math.ceil(pkt_size / size)
    # Fragmente le paquet
    for i in range(count):
        start, end = i * size, (i + 1) * size
        yield _fragment_pkt(pkt, key, iv, i, start, end)

pkt = demo_arp()
# packets = list(fragment_pkt(pkt, KEY, IV, count=3))
packets = list(fragment_pkt(pkt, KEY, count=3))
# print(packets)
wrpcap('forged_fragmented.cap', packets, append=False)
