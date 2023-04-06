from scapy.all import *
import binascii

pkt = Dot11WEP()
pkt.wepdata = "Hello, world!"
pkt.wepkeyid = 0
pkt.icv = None

raw_bytes = bytes(pkt)
icv = binascii.crc32(raw_bytes[:-4]) & 0xffffffff

pkt.icv = icv

print("Raw Bytes: ", raw_bytes)
print("Computed ICV: ", pkt.icv)
print("Expected ICV: ", pkt.ICV)

assert pkt.icv == pkt.ICV
