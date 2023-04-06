from scapy.all import *
import binascii

pkt = Dot11WEP()
pkt.wepdata = "Hello, world!"
pkt.wepkeyid = 0
pkt.icv = None

raw_bytes = bytes(pkt)
icv = binascii.crc32(raw_bytes[:-4]) & 0xffffffff

pkt.icv = icv

assert pkt.icv == struct.unpack('<I', raw_bytes[-4:])[0]
