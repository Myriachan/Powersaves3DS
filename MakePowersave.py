from __future__ import print_function
from __future__ import unicode_literals

import binascii
import codecs
import struct
import sys

if sys.version_info[0] >= 3:
    xrange = range


# Build CRC32 table.
DATEL_CRC32_TABLE = [0] * 256
for x in xrange(256):
    value = x
    for y in xrange(8):
        value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0x00000000)
    DATEL_CRC32_TABLE[x] = value


# Slightly strange Datel CRC32 means we can't use binascii.crc32.
def datel_crc32(data, crc = 0):
    for b in data:
        crc = DATEL_CRC32_TABLE[(crc & 0xFF) ^ ord(b)] ^ (crc >> 8)
    return crc


def encode_dword(x):
    return struct.pack(b"<I", x)


def syntax():
    print("Syntax: MakePowersave.py rawdata.raw output.bin \"displayname\"")
    return 1


def main(argv):
    if len(argv) != 4:
        return syntax()

    infile = open(argv[1], "rb")
    outfile = open(argv[2], "wb")

    # The description is little-endian UTF-16.
    description = codecs.encode(argv[3], "utf-16le")
    assert len(description) % 2 == 0

    # Build the basic part of the header.
    header = b''
    header += encode_dword(0x64B354D3)  # magic
    header += encode_dword(0x9C)        # size of header
    header += encode_dword(1000)        # version?
    header += encode_dword(0)           # unknown; seems always zero
    header += encode_dword(0x18)        # size of first part of header?
    assert len(header) == 0x14

    # The CRC32 of the first part of the header is written to offset 0x14.
    # The CRC32 checksums its own field, but as zero during the checksum.
    header += encode_dword(datel_crc32(header + encode_dword(0)))

    outfile.write(header)

    # Calculate Datel-CRC32 of payload.
    payload_crc = datel_crc32(b'')
    while True:
        data = infile.read(16384)
        if len(data) == 0:
            break
        payload_crc = datel_crc32(data, payload_crc)

    outfile.write(encode_dword(payload_crc))

    # Truncate the string to 64 UTF-16 characters.
    description = description[:0x40 * 2]
    if len(description) == 0x40 * 2:
        c = ord(description[0x40 * 2 - 1])
        if (c >= 0xD8) and (c <= 0xDB):
            description = description[:0x40 * 2 - 2]

    # Add NUL characters until it's maximum length.
    description += b'\0' * ((0x40 * 2) - len(description))

    outfile.write(description)

    # Write the payload.
    infile.seek(0, 0)

    while True:
        data = infile.read(16384)
        if len(data) == 0:
            break
        outfile.write(data)

    infile.close()
    outfile.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
