
from scapy.all import *
from zlib import crc32
import binascii

KEY = b'\xaa\xaa\xaa\xaa\xaa'


def pkt2bytearray(pkt):
    # str(pkt)  # => explain content
    return bytearray.fromhex(hexstr(pkt, onlyhex=True))


def compute_icv(payload):
    if isinstance(payload, str):
        payload = bytearray.fromhex(payload)
    # TODO: extract payload if parameter is a packet
    return crc32(payload)


ref_pkt = rdpcap('arp.cap')[0]
pkt = ref_pkt[Dot11WEP]

crc_text = "ecb3fa23"
crc = int(crc_text, 16)

raw_bytes = bytes(pkt)
no_crc = bytes(raw_bytes)[:-4]

# icv = compute_icv(no_crc)& 0xffffffff
icv = binascii.crc32(raw_bytes[:-4])
# pkt.icv = icv
print(crc_text)
print(crc)
print(no_crc)
print(icv)
print(icv.to_bytes(4, 'big'))
print(icv.to_bytes(4, 'little'))
# print(int(struct.pack('>I', icv), 16)[0])
# print(int(struct.pack('<I', icv), 16))
print(repr(pkt))
# d = pkt[Dot11]

# assert icv == struct.unpack('<I', raw_bytes[-4:])[0]

# for x in range(0, len(no_crc), 2):
#     tmp = compute_icv(no_crc[x:]) & 0xffffffff
#     if tmp == crc:
#         print("================OK:", x, no_crc[x:])
#         break
#     else:
#         print(x, tmp)
# else:
#     print("NOT OK")
